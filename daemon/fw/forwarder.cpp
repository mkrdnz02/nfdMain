/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2018,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "forwarder.hpp"

#include "algorithm.hpp"
#include "best-route-strategy2.hpp"
#include "strategy.hpp"
#include "core/logger.hpp"
#include "table/cleanup.hpp"
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/any.hpp>
#include <algorithm>
namespace nfd {

NFD_LOG_INIT(Forwarder);

static Name
getDefaultStrategyName()
{
  return fw::BestRouteStrategy2::getStrategyName();
}

Forwarder::Forwarder()
  : m_unsolicitedDataPolicy(new fw::DefaultUnsolicitedDataPolicy())
  , m_fib(m_nameTree)
  , m_pit(m_nameTree)
  , m_measurements(m_nameTree)
  , m_strategyChoice(*this)
{
  m_faceTable.afterAdd.connect([this] (Face& face) {
    face.afterReceiveInterest.connect(
      [this, &face] (const Interest& interest) {
        this->startProcessInterest(face, interest);
      });
    face.afterReceiveData.connect(
      [this, &face] (const Data& data) {
        this->startProcessData(face, data);
      });
    face.afterReceiveNack.connect(
      [this, &face] (const lp::Nack& nack) {
        this->startProcessNack(face, nack);
      });
    face.onDroppedInterest.connect(
      [this, &face] (const Interest& interest) {
        this->onDroppedInterest(face, interest);
      });
  });

  m_faceTable.beforeRemove.connect([this] (Face& face) {
    cleanupOnFaceRemoval(m_nameTree, m_fib, m_pit, face);
  });

  m_strategyChoice.setDefaultStrategy(getDefaultStrategyName());
}

Forwarder::~Forwarder() = default;

void
Forwarder::onIncomingInterest(Face& inFace, const Interest& interest)
{
  // receive Interest
  NFD_LOG_DEBUG("onIncomingInterest face=" << inFace.getId() <<
                " interest=" << interest.getName());
  interest.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInInterests;
  printNamePrefix("onIncomingInterest", inFace.getId(), interest.getName());
  // /localhost scope control
  bool isViolatingLocalhost = inFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(interest.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingInterest face=" << inFace.getId() <<
                  " interest=" << interest.getName() << " violates /localhost");
    // (drop)
    return;
  }

  // detect duplicate Nonce with Dead Nonce List
  bool hasDuplicateNonceInDnl = m_deadNonceList.has(interest.getName(), interest.getNonce());
  if (hasDuplicateNonceInDnl) {
    // goto Interest loop pipeline
    this->onInterestLoop(inFace, interest);
    return;
  }

  // strip forwarding hint if Interest has reached producer region
  if (!interest.getForwardingHint().empty() &&
      m_networkRegionTable.isInProducerRegion(interest.getForwardingHint())) {
    NFD_LOG_DEBUG("onIncomingInterest face=" << inFace.getId() <<
                  " interest=" << interest.getName() << " reaching-producer-region");
    const_cast<Interest&>(interest).setForwardingHint({});
  }
  // PIT insert
  shared_ptr<pit::Entry> pitEntry = m_pit.insert(interest).first;

  // detect duplicate Nonce in PIT entry
  int dnw = fw::findDuplicateNonce(*pitEntry, interest.getNonce(), inFace);
  bool hasDuplicateNonceInPit = dnw != fw::DUPLICATE_NONCE_NONE;
  if (inFace.getLinkType() == ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    // for p2p face: duplicate Nonce from same incoming face is not loop
    hasDuplicateNonceInPit = hasDuplicateNonceInPit && !(dnw & fw::DUPLICATE_NONCE_IN_SAME);
  }
  if (hasDuplicateNonceInPit) {
    // goto Interest loop pipeline
    this->onInterestLoop(inFace, interest);
    return;
  }

  // is pending?
  if (!pitEntry->hasInRecords()) {
    m_cs.find(interest,
              bind(&Forwarder::onContentStoreHit, this, std::ref(inFace), pitEntry, _1, _2),
              bind(&Forwarder::onContentStoreMiss, this, std::ref(inFace), pitEntry, _1));
  }
  else {
    this->onContentStoreMiss(inFace, pitEntry, interest);
  }
  //temporal locality
  //sendRelativeDatas(inFace, interest.getName());
}

void
Forwarder::onInterestLoop(Face& inFace, const Interest& interest)
{
  // if multi-access or ad hoc face, drop
  if (inFace.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onInterestLoop face=" << inFace.getId() <<
                  " interest=" << interest.getName() <<
                  " drop");
    return;
  }

  NFD_LOG_DEBUG("onInterestLoop face=" << inFace.getId() <<
                " interest=" << interest.getName() <<
                " send-Nack-duplicate");

  // send Nack with reason=DUPLICATE
  // note: Don't enter outgoing Nack pipeline because it needs an in-record.
  lp::Nack nack(interest);
  nack.setReason(lp::NackReason::DUPLICATE);
  inFace.sendNack(nack);
}

static inline bool
compare_InRecord_expiry(const pit::InRecord& a, const pit::InRecord& b)
{
  return a.getExpiry() < b.getExpiry();
}

void
Forwarder::onContentStoreMiss(const Face& inFace, const shared_ptr<pit::Entry>& pitEntry,
                              const Interest& interest)
{
  NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName());
  printNamePrefix("onContentStoreMiss", inFace.getId(), interest.getName());
  ++m_counters.nCsMisses;
  //addInterestCacheTable(inFace.getId(), interest.getName());//populate table
  // insert in-record
  pitEntry->insertOrUpdateInRecord(const_cast<Face&>(inFace), interest);

  // set PIT expiry timer to the time that the last PIT in-record expires
  auto lastExpiring = std::max_element(pitEntry->in_begin(), pitEntry->in_end(), &compare_InRecord_expiry);
  auto lastExpiryFromNow = lastExpiring->getExpiry() - time::steady_clock::now();
  this->setExpiryTimer(pitEntry, time::duration_cast<time::milliseconds>(lastExpiryFromNow));

  /*****************************************************/
  //Segmented Caching Strategy
  insertCacheTable(inFace.getId(), interest.getName(), interest.getNonce());
  /*****************************************************/

  // has NextHopFaceId?
  shared_ptr<lp::NextHopFaceIdTag> nextHopTag = interest.getTag<lp::NextHopFaceIdTag>();
  if (nextHopTag != nullptr) {
    // chosen NextHop face exists?
    Face* nextHopFace = m_faceTable.get(*nextHopTag);
    if (nextHopFace != nullptr) {
      NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName() << " nexthop-faceid=" << nextHopFace->getId());
      // go to outgoing Interest pipeline
      // scope control is unnecessary, because privileged app explicitly wants to forward
      this->onOutgoingInterest(pitEntry, *nextHopFace, interest);
    }
    return;
  }
  /*********************************************************/
  //Explicitly forward the interest to face based on MPPTable
  /*********************************************************/
  int isNackedElement = 0;
  FaceId fid = findFaceIdInMMPTable(interest, &isNackedElement);
  if (fid  != -1) {
	  Face* mmpNextHopFace = m_faceTable.get(fid);
	  if (mmpNextHopFace != nullptr) {
	    NFD_LOG_INFO("onContentStoreMiss interest=" << interest.getName() << " Forwarding: MPP_1111=" << mmpNextHopFace->getId());
	    // go to outgoing Interest pipeline
	    // scope control is unnecessary, because privileged app explicitly wants to forward
	    this->onOutgoingInterest(pitEntry, *mmpNextHopFace, interest);
	    return;
	  }

  }
  /*********************************************************/
  /*There is no MPP record for this interest, check previous records for any relation
  /*Calculate the probability value for this interest*/
  if(isNackedElement == 0) {
	  fid = calculateProbabilityForIncomingInterest(interest);
	  if (fid != -1) {
		  Face* mmpNextHopFace = m_faceTable.get(fid);
		  if (mmpNextHopFace != nullptr) {
			NFD_LOG_INFO("onContentStoreMiss interest=" << interest.getName() << " Forwarding: MPP_2222 =" << mmpNextHopFace->getId());
			// go to outgoing Interest pipeline
			// scope control is unnecessary, because privileged app explicitly wants to forward
			this->onOutgoingInterest(pitEntry, *mmpNextHopFace, interest);
			return;
		  }

	  }
  }
  /*********************************************************/
  printNamePrefix("onContentStoreMiss: Forwarding: NLSR BestPath", 0, interest.getName());
  // dispatch to strategy: after incoming Interest
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.afterReceiveInterest(inFace, interest, pitEntry); });

}

void
Forwarder::onContentStoreHit(const Face& inFace, const shared_ptr<pit::Entry>& pitEntry,
                             const Interest& interest, const Data& data)
{
  NFD_LOG_DEBUG("onContentStoreHit interest=" << interest.getName());
  ++m_counters.nCsHits;

  data.setTag(make_shared<lp::IncomingFaceIdTag>(face::FACEID_CONTENT_STORE));
  // XXX should we lookup PIT for other Interests that also match csMatch?

  pitEntry->isSatisfied = true;
  pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

  // set PIT expiry timer to now
  this->setExpiryTimer(pitEntry, 0_ms);

  // dispatch to strategy: after Content Store hit
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.afterContentStoreHit(pitEntry, inFace, data); });

  /****************************************/
  //Caching Strategy
  processHitDataSegment(inFace.getId(), data);
  /****************************************/
}
/****************************************/
void Forwarder::updateNeighborsList(const FaceId& faceId, const Name& name) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix, routerName;
	size_t				pos;
	int 				isFound, linkCost = 0xFF;
	/*--------------------------*/
	osNamePrefix << name;
	namePrefix 	= osNamePrefix.str();
	//check hello interest
	pos = namePrefix.find("/nlsr/INFO");
	if(pos == std::string::npos){
		return;
	}
	namePrefix = namePrefix.substr(0, pos);
	//NFD_LOG_INFO("updateNeighborsList: name=" << namePrefix);
	//check already exist
	isFound = 0;
	for(struct fib::M_FaceId_Name_Struct node: m_fib.m_neighborsList) {
		if(node.faceId == faceId) {
			isFound = 1;
			break;
		}
	}

	if (isFound == 1) {
		return;
	}

	linkCost = getLinkCostForThisHop(faceId);

	if(linkCost == 0 || linkCost == 32766) {
		return;
	}
	NFD_LOG_INFO("neighbors: name=" << namePrefix << ", FaceId = " << faceId << ", cost = " << linkCost);
	//add into table
	try {
		struct fib::M_FaceId_Name_Struct node;
		node.name 			= namePrefix;
		node.faceId 		= faceId;
		m_fib.m_neighborsList.push_back(node);
	} catch (std::bad_alloc& ba) {
		NFD_LOG_DEBUG("...bad_alloc error.");
	}

}

void Forwarder::sendMPPTableToNeighbors(const FaceId& faceId) {
    ndn::Data *data = new ndn::Data();
    std::string mppInterestPrefix = "ndn:/mpp/ProudToShare";
    std::string mppTableStr = "";
	uint32_t pVal = 0;
	/*for (const fib::NextHop& hop : m_fib) {
		NFD_LOG_INFO("...fib hop id = " << hop.getFace() << ", cost = " << hop.getCost());
	}*/
	for(struct fib::M_MPPTable_Struct node: m_fib.m_MPPTable){

		pVal  = (uint32_t)(node.hop << 16) | node.cost;
		//NFD_LOG_INFO("sendMPPTableToNeighbors: node.cost= " << node.cost << ", node.hop= " << node.hop << ", pVal = " << pVal);
		mppTableStr += to_string(pVal) + "#" + node.name + "#";

	}
    //create a data
    data->setName(ndn::Name(mppInterestPrefix).appendVersion());
    data->setFreshnessPeriod(ndn::time::seconds(10)); // 10 sec
    //NFD_LOG_INFO("sendMPPTableToNeighbors mppTableStr:" << mppTableStr);
    data->setContent((const uint8_t*)(mppTableStr.c_str()), mppTableStr.size());
    ndn::security::v2::KeyChain m_keyChain;
    m_keyChain.sign(*data);

    for(struct fib::M_FaceId_Name_Struct node: m_fib.m_neighborsList) {
    	if(node.faceId == faceId) {
    		//skip downstream
    		continue;
    	}
        nfd::face::Face* outFace = m_faceTable.get(node.faceId);
        if (outFace != nullptr) {
        	//NFD_LOG_INFO("sendMPPTableToNeighbors data=" << mppInterestPrefix << " outfaceid=" << outFace->getId());
        	this->onOutgoingData(*data, *outFace);
        }
    }
}

int Forwarder::isFaceInNeighborList(const FaceId& faceId) {

	if(m_fib.m_neighborsList.size() > 0 ) {
		for(struct fib::M_FaceId_Name_Struct node: m_fib.m_neighborsList) {
			if(node.faceId == faceId) {
				return 1;
			}
		}
	}
	return 0;
}

FaceId Forwarder::findFaceIdInMMPTable(const Interest& interest, int* nackElem ) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	size_t				pos;
	/*--------------------------*/
	osNamePrefix << interest.getName();
	namePrefix 	= osNamePrefix.str();
	//check neighbor list


	*nackElem = 0;
	for(int i = 0; i < m_fib.m_MPPTable.size(); i++){
		pos = namePrefix.find(m_fib.m_MPPTable[i].name);
		if(pos != std::string::npos){
			//NFD_LOG_INFO("findFaceIdInMMPTable: name:" << node.name << ", nackCnt= " << node.nackCnt);
			//return if it has been not nacked before
			if ( ( isFaceInNeighborList(m_fib.m_MPPTable[i].faceId)) &&
				 ( m_fib.m_MPPTable[i].nackCnt == 0) )
			{
				m_fib.m_MPPTable[i].inUse = 1;
				return m_fib.m_MPPTable[i].faceId;
			}

			*nackElem = 1;
			//no need to continue
			break;
		}
	}
	return -1;
}

void Forwarder::checkMPPRecordInUseFlag(const Name& name, const int type, const FaceId& faceId) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	size_t				pos;
	/*--------------------------*/
	osNamePrefix << name;
	namePrefix 	= osNamePrefix.str();
	//check name
	for(uint32_t i = 0; i < m_fib.m_MPPTable.size(); i++){

		pos = namePrefix.find(m_fib.m_MPPTable[i].name);
		if(pos != std::string::npos){

			if (m_fib.m_MPPTable[i].inUse == 1) {

				//check type of sending function
				if(type == 0) {//NACK
					//increase nacked counter
					m_fib.m_MPPTable[i].nackCnt++;
					return;
				}
				else if(type == 1){//INCOMING DATA
					//increase nacked counter
					m_fib.m_MPPTable[i].inUse 	= 0;
					m_fib.m_MPPTable[i].nackCnt = 0;
					return;
				}
			}
		}
	}
	//check probability table
	if (type == 1) {
		for(uint32_t i = 0; i < m_fib.m_CalcProbTable.size(); i++) {
				pos = namePrefix.find(m_fib.m_MPPTable[i].name);
				if((pos != std::string::npos) &&  m_fib.m_MPPTable[i].faceId == faceId){
					m_fib.m_MPPTable.erase(m_fib.m_MPPTable.begin() + i);
					return;
				}
		}
	}
}
int Forwarder::isNamePrefixExistInCalcProbTable(const std::string name) {
	size_t	pos;
	for (struct fib::M_FaceId_Name_Struct node: m_fib.m_CalcProbTable) {
		pos = name.find(node.name);
		if(pos != std::string::npos){
			return 1;
		}
	}
	return 0;
}

FaceId Forwarder::calculateProbabilityForIncomingInterest(const Interest& interest) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::vector<std::string> inputVal, tableVal;
	unsigned int prevMatchCnt, curMatchCnt, sizeOfinputVal, cur_mean, cur_size;
	size_t				pos;
	/*--------------------------*/
	osNamePrefix << interest.getName();
	namePrefix 	= osNamePrefix.str();
	//is already used?
	if(isNamePrefixExistInCalcProbTable(namePrefix)) {
		return -1;
	}
	//check black name list prefix
	for(std::string l: nameBlackList){
		pos = namePrefix.find(l);
		if(pos != std::string::npos){
			return -1;
		}
	}

	NFD_LOG_INFO("calculateProbabilityForIncomingInterest = " << namePrefix);
	//divide the each sub prefix into the list
	boost::split(inputVal, namePrefix, boost::is_any_of("/"));
	sizeOfinputVal = inputVal.size();
	//reset the counter
	prevMatchCnt = 0;
	FaceId f_id = -1;
	for(struct fib::M_FaceId_Name_Struct neigNode: m_fib.m_neighborsList) {
		cur_mean = 0;
		cur_size = 0;
		for(struct fib::M_MPPTable_Struct node: m_fib.m_MPPTable){
			if(neigNode.faceId != node.faceId) {
				continue;
			}
			//divide the each sub prefix of table row into the list
			boost::split(tableVal, node.name, boost::is_any_of("/"));
			curMatchCnt = 0;
			for (unsigned int i = 1; i < sizeOfinputVal; i++) {
						if(tableVal.size() > i) {
							if(tableVal[i] == inputVal[i]){
								curMatchCnt++;
							}
							else {
								//order of match matter
								break;
							}
						}
			}
			cur_mean = cur_mean * cur_size;
			cur_mean += ( (curMatchCnt*100) / (tableVal.size()-1) );
			//increment size
			cur_size++;
			cur_mean = cur_mean / cur_size;

			if(cur_mean > prevMatchCnt) {
				prevMatchCnt = cur_mean;
				if(prevMatchCnt > 50) {
					f_id = node.faceId; //store the faceId having the most match counter
				}
			}
		}//mpp table record loop
	}//neighbor list loop

	if(f_id != -1) {
		NFD_LOG_INFO("...Forwarding : " << f_id << ", calc probability = %" << prevMatchCnt);

	    try {
	    	struct fib::M_FaceId_Name_Struct node;
	    	node.name 			= namePrefix;
	    	node.faceId 		= f_id;
	    	m_fib.m_CalcProbTable.push_back(node);
	    } catch (std::bad_alloc& ba) {
	    	NFD_LOG_DEBUG("...bad_alloc error.");
	    	return -1;
	    }

		return f_id;
	}

	return -1;
}

void Forwarder::printNamePrefix(const std::string info, const FaceId& faceId, const Name& name) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	size_t				pos;
	/*--------------------------*/
	//get the segment portion from the name prefix
	osNamePrefix << name;
	namePrefix 	= osNamePrefix.str();

	//check black name list prefix
	for(std::string l: nameBlackList){
		pos = namePrefix.find(l);
		if(pos != std::string::npos){
			return;
		}
	}
	// receive Interest
	NFD_LOG_INFO(info << ", face=" << faceId <<  ", name=" << name);
}
void Forwarder::dumpMPPTable() {
	if(m_fib.m_MPPTable.size() > 0) {
		NFD_LOG_INFO("_MPPTable_:");
		for(struct fib::M_MPPTable_Struct n: m_fib.m_MPPTable) {
			NFD_LOG_INFO("...Name = " << n.name << ", inFaceId = " << n.faceId <<
						 ", probability = " << n.probability << ", hop = " << n.hop <<
						 ", cost = " << n.cost << ", nackCnt = " << n.nackCnt);
		}
	}
}
std::string Forwarder::getRouterName(const FaceId& faceId) {

	for(struct fib::M_FaceId_Name_Struct node: m_fib.m_neighborsList) {
		if(node.faceId == faceId) {
			return node.name;
		}
	}
	return "null";
}

uint32_t Forwarder::getLinkCostForThisHop(const FaceId& faceId) {
	std::ostringstream 	osNamePrefix;
	std::string 		routerName;
	uint32_t linkCost = 0xFFFF;
	//*******************************************
	for (const auto& entry : m_fib) {
	    const auto& nexthops = entry.getNextHops();
	    //get the name of the fib entry
	    osNamePrefix.str("");
	    osNamePrefix.clear();
	    osNamePrefix << entry.getPrefix();
	    routerName = osNamePrefix.str();

	    if ( routerName.compare(getRouterName(faceId)) == 0 ) {
	    	for (int i = 0; i < nexthops.size(); i++) {
				if(faceId == nexthops[i].getFace().getId()) {
					linkCost = nexthops[i].getCost();
					NFD_LOG_INFO("m_fib_list: name=" << routerName << ", FaceId = " << faceId << ", cost = " << linkCost);
					break;
				}
			}
	    }
	}

	return linkCost;
}

void Forwarder::getSharedMPPTable(const FaceId& faceId, const Data& data) {
	std::ostringstream 	osNamePrefix;
	std::ostringstream 	osContentStream;
	std::string 		namePrefix, routerName, contentStrFull, h, contentString;
	std::vector<std::string> rowList;
	size_t				pos, pos2;
	Block content;
	char buf[16];
	int toggleBit;
	uint32_t pVal = 0, linkCost = 0;
	/*--------------------------*/
	//get the segment portion from the name prefix
	osNamePrefix << data.getName();
	namePrefix 	= osNamePrefix.str();
	//check if someone is sharing its mpp table
	pos = namePrefix.find("ProudToShare");
	if(pos == std::string::npos){
		return;
	}

	//*******************************************
	linkCost = getLinkCostForThisHop(faceId);
	//NFD_LOG_INFO("m_fib_list: name=" << routerName << ", FaceId = " << faceId << ", cost = " << linkCost);



	//It is shared data from neighbors
	NFD_LOG_INFO("getSharedMPPTable: <ProudToShare> FaceId = " << faceId << ", Name = " << namePrefix);

	osContentStream << data.getContent();
	contentStrFull = osContentStream.str();

	//NFD_LOG_INFO("getSharedMPPTable: <ProudToShare> data : " << contentStrFull);
	//find the "=" sign position
	pos2 = contentStrFull.find("=");
	if(pos2 == std::string::npos){
		NFD_LOG_INFO("... '=' not found");
		return;
	}

	//NFD_LOG_INFO("addMPPStatisticTable: pos2 + 1: " << (pos2 + 1) << ", contentStrFull.size(): " << contentStrFull.size());
	//construct the original shared data as string value
	contentString = "";
	for(unsigned int i = (pos2 + 1); i < contentStrFull.size(); i += 2) {
		//get the two digit for hex conversion
		h = contentStrFull.substr(i, 2);
		sprintf(buf, "%c", std::stoi(h, 0 , 16));
		contentString += buf;
	}
	//shared data, split and add into local mpp table
	uint32_t probability;
	uint32_t cost;
	uint32_t hop;

	NFD_LOG_INFO("...Data: " << contentString);
	rowList.clear();
	boost::split(rowList, contentString, boost::is_any_of("#"));
	if(rowList.size() > 0 ) {
		toggleBit = 0;
		for(std::string nPrefix: rowList) {
			if(nPrefix == "") {
				continue;
			}

			if(toggleBit == 0) {//probability
				pVal 		 = std::stoi(nPrefix);
				//NFD_LOG_INFO("...pVal = " << pVal);
				probability  = 100;
				cost 		 = (pVal & 0x0000FFFF) + linkCost;
				hop 		 = (pVal >> 16) + 1; //increment hop by 1
				toggleBit = 1;
			}
			else {//namePrefix
				//NFD_LOG_INFO("...try to save: nPrefix: " << nPrefix << ", pVal:" << pVal);
				//NFD_LOG_INFO("...probability = " << probability << ", cost= " << cost << ", hop= " << hop);
				addMPPStatisticTable(faceId, nPrefix, probability, cost, hop);
				toggleBit = 0;
			}
		}
	}

}
//MPP entries for the MPP forwarding strategy
void Forwarder::addMPPStatisticTable(const FaceId& faceId, const Data& data) {
	std::ostringstream 	osNamePrefix;
	std::ostringstream 	osContentStream;
	std::string 		namePrefix;
	size_t				pos;

	//get the segment portion from the name prefix
	osNamePrefix << data.getName();
	namePrefix 	= osNamePrefix.str();

	//check black name list prefix
	for(std::string l: nameBlackList){
		pos = namePrefix.find(l);
		if(pos != std::string::npos){
			return;
		}
	}
	//remove version part
	pos = namePrefix.find("/%FD");
	if(pos != std::string::npos){
		namePrefix = namePrefix.substr(0, pos);
	}
	//send the faceId and name prefix to insert into the table
	addMPPStatisticTable(faceId, namePrefix, 100 , 0, 0);

}
void Forwarder::addMPPStatisticTable(const FaceId& faceId, const std::string namePrefix, const uint32_t probability, const uint32_t cost, const uint32_t hop) {
	size_t	pos;
	//NFD_LOG_INFO("...Name = " << namePrefix << ", FaceId = " << faceId <<
	//			 ", hop = " << hop << ", cost = " << cost);
	//check the faceid if it is a valid neighbor

	//check the table if incoming interest already exists
	for(uint32_t i = 0; i < m_fib.m_MPPTable.size(); i++) {
		pos = namePrefix.find(m_fib.m_MPPTable[i].name);
		if(pos != std::string::npos){
			//compare the values
			if((hop*cost) < (m_fib.m_MPPTable[i].hop*m_fib.m_MPPTable[i].cost)) {

				m_fib.m_MPPTable[i].faceId 		= faceId;
				m_fib.m_MPPTable[i].hop	 		= hop;
				m_fib.m_MPPTable[i].cost	 	= cost;
				m_fib.m_MPPTable[i].probability = probability;
				m_fib.m_MPPTable[i].nackCnt 	= 0;
				m_fib.m_MPPTable[i].inUse		= 0;
				//NFD_LOG_INFO("...Updated.");
				dumpMPPTable();
				//share MPP Table
				sendMPPTableToNeighbors(faceId);
			}

			//return if there is match
			return;
		}
	}

	//otherwise create a new node
	if(m_fib.m_MPPTable.size() > 1000){
		return;
	}

    try {
    	struct fib::M_MPPTable_Struct node;
    	node.name 			= namePrefix;
    	node.faceId 		= faceId;
    	node.probability 	= probability;
    	node.cost			= cost;
    	node.hop			= hop;
    	node.nackCnt		= 0;
    	node.inUse			= 0;
    	m_fib.m_MPPTable.push_back(node);
    	dumpMPPTable();
    	//share MPP Table
    	sendMPPTableToNeighbors(faceId);
    }
    catch (std::bad_alloc& ba) {
    	NFD_LOG_DEBUG("...bad_alloc error.");
    	return;
    }
}

int Forwarder::isDataSegmented(const Name& name) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::string 		segment_str;
	size_t				pos;
	int					segment_no;
	/*--------------------------*/
	//get the segment portion from the name prefix
	osNamePrefix << name;
	namePrefix 	= osNamePrefix.str();
	//check black name list prefix
	for(std::string l: nameBlackList){
		pos = namePrefix.find(l);
		if(pos != std::string::npos){
			return 0;
		}
	}

	pos = namePrefix.find("/%00");
	if(pos == std::string::npos) {
		return 0;
	}
	//check is valid segment
	segment_str = namePrefix.substr(pos);
	if(segment_str.length() != 7) {
		return 0;
	}

	return 1;
}
//PIT entries for the data segments coming producer
void Forwarder::insertCacheTable(const FaceId& faceId, const Name& name, const uint32_t nonce){
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::string 		segment_str;
	size_t				pos;
	int					segment_no;
	/*--------------------------*/
	/*remove the expired records*/
	/*--------------------------*/
	for(unsigned int i = 0; i < m_fib.m_CacheTable.size(); i++) {
		if(std::abs(m_fib.m_CacheTable[i].createTime - std::time(0)) > 600){ //10min
			m_fib.m_CacheTable.erase(m_fib.m_CacheTable.begin() + i);
		}
	}
	//check neighbor
	if (isFaceInNeighborList(faceId) == 0) {
		return;
	}
	/*--------------------------*/
	//get the segment portion from the name prefix
	osNamePrefix << name;
	namePrefix 	= osNamePrefix.str();
	//check black name list prefix
	for(std::string l: nameBlackList){
		pos = namePrefix.find(l);
		if(pos != std::string::npos){
			return;
		}
	}

	pos = namePrefix.find("/%00");
	if(pos == std::string::npos) {
		NFD_LOG_DEBUG("insertCacheTable: Error npos");
		return;
	}
	//check is valid segment
	segment_str = namePrefix.substr(pos);
	if(segment_str.length() != 7) {
		NFD_LOG_DEBUG("insertCacheTable: Error sizeLessThan7");
		return;
	}
	//get segment no
	segment_no = std::stoi(segment_str.substr(5,5), 0 , 16);
	//buffer{segment_str.substr(5,5)}; buffer >> hex >> segment_no;
	namePrefix = namePrefix.substr(0, pos);
	//check inFace
	for(int i = 0; i < m_fib.m_CacheTable.size(); i++) {

		pos = namePrefix.find(m_fib.m_CacheTable[i].name);
		if((pos != std::string::npos) && (m_fib.m_CacheTable[i].inFaceId == faceId)){
			return;
		}
	}
	NFD_LOG_INFO("insertCacheTable: Name = " << namePrefix << ", FaceId = " << faceId);
	//Everything is okay, now add the name into table
	NFD_LOG_INFO("...Name = " << namePrefix << ", FaceId = " << faceId << ", ReqSegment = " << segment_no);

	//otherwise create a new node
    try {
    	struct fib::M_CacheTable_Struct node;
    	node.name 		= namePrefix;
    	node.inFaceId	= faceId;
    	node.nonce		= nonce;
    	node.reqSegment	= segment_no;
    	node.createTime = std::time(0); //timestamp for record deletiton
    	m_fib.m_CacheTable.push_back(node);
    }
    catch (std::bad_alloc& ba) {
    	NFD_LOG_DEBUG("insertCacheTable: bad_alloc error.");
    	return;
    }
}
/*Find the list of the requester for the original data and send the rest of the segments*/
void Forwarder::processHitDataSegment(const FaceId& faceId, const Data& data) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::string 		segment_str;
	size_t				pos;
	int					segment_no = 0;
	std::vector<ndn::Data> segDataList;
	//get the segment portion from the name prefix
	try {

		//check neighbor
		if (isFaceInNeighborList(faceId) == 0) {
			return;
		}

		osNamePrefix << data.getName();
		namePrefix 	= osNamePrefix.str();
		//check black name list prefix
		for(std::string l: nameBlackList){
			pos = namePrefix.find(l);
			if(pos != std::string::npos){
				return;
			}
		}

		pos = namePrefix.find("/%00");
		if(pos == std::string::npos) {
			NFD_LOG_INFO("...: Error up_npos");
			return;
		}
		//check is valid segment
		segment_str = namePrefix.substr(pos);
		if(segment_str.length() != 7) {
			NFD_LOG_INFO("...: Error up_sizeLessThan7: " << segment_str.length());
			return;
		}

		namePrefix = namePrefix.substr(0, pos);
		segment_no = std::stoi(segment_str.substr(5,5), 0 , 16);

		NFD_LOG_INFO("processHitDataSegment: searching: name = " << namePrefix << ", outFace = " << faceId << ", req_seg = " << segment_no);
		//get datas from Content Store
		m_cs.lookOtherSegmentsInContentStoreTable(&segDataList, namePrefix, segment_no);
		for(int i = 0; i < segDataList.size(); i++){

			Face *outFace 	= m_faceTable.get(faceId);
			if(outFace != nullptr) {
				outFace->sendData(segDataList[i]);
				++m_counters.nOutData;
				NFD_LOG_INFO("...found: name = " << segDataList[i].getName() << ", outFace = " << faceId);

			}
		}

	}
	catch(std::exception e) {
		//do nothing
	}
}

void Forwarder::processIncomingDataSegments(const Data& data) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::string 		segment_str;
	std::string			keyPrefix;
	size_t				pos;
	int					segment_no = 0, isSegmentNoExist;

	//get the segment portion from the name prefix
	try {
		osNamePrefix << data.getName();
		namePrefix 	= osNamePrefix.str();
		//check black name list prefix
		for(std::string l: nameBlackList){
			pos = namePrefix.find(l);
			if(pos != std::string::npos){
				return;
			}
		}

		pos = namePrefix.find("/%00");
		if(pos == std::string::npos) {
			NFD_LOG_DEBUG("sendOtherDataSegments: Error hit_npos");
			return;
		}
		//check is valid segment
		segment_str = namePrefix.substr(pos);
		if(segment_str.length() != 7) {
			NFD_LOG_DEBUG("sendOtherDataSegments: Error hit_sizeLessThan7");
			return;
		}

		namePrefix = namePrefix.substr(0, pos);
		segment_no = std::stoi(segment_str.substr(5,5), 0 , 16);

		NFD_LOG_INFO("processIncomingDataSegments: name = " << namePrefix << ", seg = " << segment_no);

		for(int i = 0; i < m_fib.m_CacheTable.size(); i++) {

			pos = namePrefix.find(m_fib.m_CacheTable[i].name);
			if(pos != std::string::npos){
				isSegmentNoExist = 0;
				/*for(int sentSegments: m_fib.m_CacheTable[i].segmentUpList) {
					if(segment_no == sentSegments) {
						isSegmentNoExist = 1;
					}
				}*/

				//send the data to the up stream if the segment no does not exist.
				if(isSegmentNoExist == 0) {
					FaceId fid 		= m_fib.m_CacheTable[i].inFaceId;
					Face *outFace 	= m_faceTable.get(fid);
					if(outFace != nullptr) {
						//send
						outFace->sendData(data);
						m_fib.m_CacheTable[i].segmentUpList.push_back(segment_no);
						NFD_LOG_INFO("...sent: name = " << namePrefix << ", outFace = " << fid << ", seg = " << segment_no);
					}
				}

			}
		}//m_fib.m_CacheTable entries
	}
	catch(std::exception e) {
		//do nothing
	}
}

/****************************************/
void
Forwarder::onOutgoingInterest(const shared_ptr<pit::Entry>& pitEntry, Face& outFace, const Interest& interest)
{
  NFD_LOG_DEBUG("onOutgoingInterest face=" << outFace.getId() <<
                " interest=" << pitEntry->getName());

  // insert out-record
  pitEntry->insertOrUpdateOutRecord(outFace, interest);

  // send Interest
  outFace.sendInterest(interest);
  ++m_counters.nOutInterests;
}

void
Forwarder::onInterestFinalize(const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("onInterestFinalize interest=" << pitEntry->getName() <<
                (pitEntry->isSatisfied ? " satisfied" : " unsatisfied"));

  // Dead Nonce List insert if necessary
  this->insertDeadNonceList(*pitEntry, 0);

  // PIT delete
  scheduler::cancel(pitEntry->expiryTimer);
  m_pit.erase(pitEntry.get());
}

void
Forwarder::onIncomingData(Face& inFace, const Data& data)
{
  // receive Data
	NFD_LOG_DEBUG("onIncomingData face=" << inFace.getId() << " data=" << data.getName());
  data.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInData;
  /***********************************************************/
  uint32_t dataPathCost = getLinkCostForThisHop(inFace.getId());
  int dataSavePolicyFlag = 0;
  shared_ptr<lp::DataPathCostTag> tag_ptr = data.getTag<lp::DataPathCostTag>();
  if (tag_ptr != nullptr) {
	  dataPathCost = (tag_ptr->get() + dataPathCost);
	  if(dataPathCost > 100) {
		  dataSavePolicyFlag = 1;
		  data.setTag(make_shared<lp::DataPathCostTag>(0));
	  }
	  else {
		  data.setTag(make_shared<lp::DataPathCostTag>(dataPathCost));
	  }
	  NFD_LOG_INFO("onIncomingData data=" << data.getName() << ", costUpTo = " << dataPathCost);
  }
  else {
	  dataSavePolicyFlag = 2;
  }

  printNamePrefix("onIncomingData", inFace.getId(), data.getName());
  updateNeighborsList(inFace.getId(), data.getName());
  getSharedMPPTable(inFace.getId(), data);
  /**********************************************/
  /***********Check MPP Table********************/
  checkMPPRecordInUseFlag(data.getName(), 1, inFace.getId());
  /**********************************************/
  /***********************************************************/
  // /localhost scope control
  bool isViolatingLocalhost = inFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingData face=" << inFace.getId() <<
                  " data=" << data.getName() << " violates /localhost");
    // (drop)
    return;
  }

  // PIT match
  pit::DataMatchResult pitMatches = m_pit.findAllDataMatches(data);
  if (pitMatches.size() == 0) {
    // goto Data unsolicited pipeline
    this->onDataUnsolicited(inFace, data, dataSavePolicyFlag);
    return;
  }

  // CS insert
  if(dataSavePolicyFlag != 0) {
	  m_cs.insert(data);
  }
  // when only one PIT entry is matched, trigger strategy: after receive Data
  if (pitMatches.size() == 1) {
    auto& pitEntry = pitMatches.front();

    NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());
    printNamePrefix("...onIncomingData matching", inFace.getId(), pitEntry->getName());
    // set PIT expiry timer to now
    this->setExpiryTimer(pitEntry, 0_ms);

    // trigger strategy: after receive Data
    this->dispatchToStrategy(*pitEntry,
      [&] (fw::Strategy& strategy) { strategy.afterReceiveData(pitEntry, inFace, data); });

    // mark PIT satisfied
    pitEntry->isSatisfied = true;
    pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

    // Dead Nonce List insert if necessary (for out-record of inFace)
    this->insertDeadNonceList(*pitEntry, &inFace);
    // delete PIT entry's out-record
    pitEntry->deleteOutRecord(inFace);
  }
  // when more than one PIT entry is matched, trigger strategy: before satisfy Interest,
  // and send Data to all matched out faces
  else {
    std::set<Face*> pendingDownstreams;
    auto now = time::steady_clock::now();

    for (const shared_ptr<pit::Entry>& pitEntry : pitMatches) {
      NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());
      printNamePrefix("...onIncomingData matching", inFace.getId(), pitEntry->getName());
      // remember pending downstreams
      for (const pit::InRecord& inRecord : pitEntry->getInRecords()) {
        if (inRecord.getExpiry() > now) {
          pendingDownstreams.insert(&inRecord.getFace());
        }
      }

      // set PIT expiry timer to now
      this->setExpiryTimer(pitEntry, 0_ms);

      // invoke PIT satisfy callback
      this->dispatchToStrategy(*pitEntry,
        [&] (fw::Strategy& strategy) { strategy.beforeSatisfyInterest(pitEntry, inFace, data); });

      // mark PIT satisfied
      pitEntry->isSatisfied = true;
      pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

      // Dead Nonce List insert if necessary (for out-record of inFace)
      this->insertDeadNonceList(*pitEntry, &inFace);

      // clear PIT entry's in and out records
      pitEntry->clearInRecords();
      pitEntry->deleteOutRecord(inFace);
    }

    // foreach pending downstream
    for (Face* pendingDownstream : pendingDownstreams) {
      if (pendingDownstream->getId() == inFace.getId() &&
          pendingDownstream->getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) {
        continue;
      }
      // goto outgoing Data pipeline
      this->onOutgoingData(data, *pendingDownstream);
      printNamePrefix("...onIncomingData onOutgoingData", pendingDownstream->getId(), data.getName());
    }
  }
  //statistic table
  addMPPStatisticTable(inFace.getId(), data);//populate table
}

void
Forwarder::onDataUnsolicited(Face& inFace, const Data& data, const uint32_t flag)
{
  bool isDataNotCached;
  int isDataCached = 0;

  processIncomingDataSegments(data);
  if(flag == 0) {
	  return;
  }

  // accept to cache?
  fw::UnsolicitedDataDecision decision = m_unsolicitedDataPolicy->decide(inFace, data);
  if (decision == fw::UnsolicitedDataDecision::CACHE) {
    // CS insert
	m_cs.insert(data, true);
    isDataCached = 1;
  }

  if( ( isFaceInNeighborList(inFace.getId()) == 1) &&
	  ( isDataCached == 0) &&
	  ( isDataSegmented(data.getName()) == 1) ) {

	  m_cs.insert(data, true);
  }

  NFD_LOG_DEBUG("onDataUnsolicited face=" << inFace.getId() <<
                " data=" << data.getName() <<
                " decision=" << decision);
}

void
Forwarder::onOutgoingData(const Data& data, Face& outFace)
{
  if (outFace.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingData face=invalid data=" << data.getName());
    return;
  }
  NFD_LOG_DEBUG("onOutgoingData face=" << outFace.getId() << " data=" << data.getName());

  // /localhost scope control
  bool isViolatingLocalhost = outFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onOutgoingData face=" << outFace.getId() <<
                  " data=" << data.getName() << " violates /localhost");
    // (drop)
    return;
  }

  // TODO traffic manager

  // send Data
  outFace.sendData(data);
  ++m_counters.nOutData;
}

void
Forwarder::onIncomingNack(Face& inFace, const lp::Nack& nack)
{
  // receive Nack
  nack.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInNacks;
  /**********************************************/
  /***********Check MPP Table********************/
  checkMPPRecordInUseFlag(nack.getInterest().getName(), 0, inFace.getId());
  /**********************************************/
  // if multi-access or ad hoc face, drop
  if (inFace.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " face-is-multi-access");
    return;
  }

  // PIT match
  shared_ptr<pit::Entry> pitEntry = m_pit.find(nack.getInterest());
  // if no PIT entry found, drop
  if (pitEntry == nullptr) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " no-PIT-entry");
    return;
  }

  // has out-record?
  pit::OutRecordCollection::iterator outRecord = pitEntry->getOutRecord(inFace);
  // if no out-record found, drop
  if (outRecord == pitEntry->out_end()) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " no-out-record");
    return;
  }

  // if out-record has different Nonce, drop
  if (nack.getInterest().getNonce() != outRecord->getLastNonce()) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " wrong-Nonce " <<
                  nack.getInterest().getNonce() << "!=" << outRecord->getLastNonce());
    return;
  }

  NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                " nack=" << nack.getInterest().getName() <<
                "~" << nack.getReason() << " OK");

  // record Nack on out-record
  outRecord->setIncomingNack(nack);

  // set PIT expiry timer to now when all out-record receive Nack
  if (!fw::hasPendingOutRecords(*pitEntry)) {
    this->setExpiryTimer(pitEntry, 0_ms);
  }

  // trigger strategy: after receive NACK
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.afterReceiveNack(inFace, nack, pitEntry); });
}

void
Forwarder::onOutgoingNack(const shared_ptr<pit::Entry>& pitEntry, const Face& outFace,
                          const lp::NackHeader& nack)
{
  if (outFace.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingNack face=invalid" <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " no-in-record");
    return;
  }

  // has in-record?
  pit::InRecordCollection::iterator inRecord = pitEntry->getInRecord(outFace);

  // if no in-record found, drop
  if (inRecord == pitEntry->in_end()) {
    NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " no-in-record");
    return;
  }

  // if multi-access or ad hoc face, drop
  if (outFace.getLinkType() != ndn::nfd::LINK_TYPE_POINT_TO_POINT) {
    NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " face-is-multi-access");
    return;
  }

  NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                " nack=" << pitEntry->getInterest().getName() <<
                "~" << nack.getReason() << " OK");

  // create Nack packet with the Interest from in-record
  lp::Nack nackPkt(inRecord->getInterest());
  nackPkt.setHeader(nack);

  // erase in-record
  pitEntry->deleteInRecord(outFace);

  // send Nack on face
  const_cast<Face&>(outFace).sendNack(nackPkt);
  ++m_counters.nOutNacks;
}

void
Forwarder::onDroppedInterest(Face& outFace, const Interest& interest)
{
  m_strategyChoice.findEffectiveStrategy(interest.getName()).onDroppedInterest(outFace, interest);
}

void
Forwarder::setExpiryTimer(const shared_ptr<pit::Entry>& pitEntry, time::milliseconds duration)
{
  BOOST_ASSERT(duration >= 0_ms);

  scheduler::cancel(pitEntry->expiryTimer);

  pitEntry->expiryTimer = scheduler::schedule(duration, [=] { onInterestFinalize(pitEntry); });
}

void
Forwarder::insertDeadNonceList(pit::Entry& pitEntry, Face* upstream)
{
  // need Dead Nonce List insert?
  bool needDnl = true;
  if (pitEntry.isSatisfied) {
    BOOST_ASSERT(pitEntry.dataFreshnessPeriod >= 0_ms);
    needDnl = static_cast<bool>(pitEntry.getInterest().getMustBeFresh()) &&
              pitEntry.dataFreshnessPeriod < m_deadNonceList.getLifetime();
  }

  if (!needDnl) {
    return;
  }

  // Dead Nonce List insert
  if (upstream == nullptr) {
    // insert all outgoing Nonces
    const auto& outRecords = pitEntry.getOutRecords();
    std::for_each(outRecords.begin(), outRecords.end(), [&] (const auto& outRecord) {
      m_deadNonceList.add(pitEntry.getName(), outRecord.getLastNonce());
    });
  }
  else {
    // insert outgoing Nonce of a specific face
    auto outRecord = pitEntry.getOutRecord(*upstream);
    if (outRecord != pitEntry.getOutRecords().end()) {
      m_deadNonceList.add(pitEntry.getName(), outRecord->getLastNonce());
    }
  }
}

} // namespace nfd
