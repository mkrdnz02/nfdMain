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
  dumpMPPTable();
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
  ++m_counters.nCsMisses;
  //addInterestCacheTable(inFace.getId(), interest.getName());//populate table
  // insert in-record
  pitEntry->insertOrUpdateInRecord(const_cast<Face&>(inFace), interest);

  // set PIT expiry timer to the time that the last PIT in-record expires
  auto lastExpiring = std::max_element(pitEntry->in_begin(), pitEntry->in_end(), &compare_InRecord_expiry);
  auto lastExpiryFromNow = lastExpiring->getExpiry() - time::steady_clock::now();
  this->setExpiryTimer(pitEntry, time::duration_cast<time::milliseconds>(lastExpiryFromNow));

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
  //Explicitly forward the interest to face based on MPPTable
  FaceId fid = findFaceIdInMMPTable(interest);
  if (fid  != 0) {
	  Face* mmpNextHopFace = m_faceTable.get(fid);
	  if (mmpNextHopFace != nullptr) {
	    NFD_LOG_INFO("onContentStoreMiss interest=" << interest.getName() << " mmpNextHopFace-faceid=" << mmpNextHopFace->getId());
	    // go to outgoing Interest pipeline
	    // scope control is unnecessary, because privileged app explicitly wants to forward
	    this->onOutgoingInterest(pitEntry, *mmpNextHopFace, interest);
	  }
	  return;
  }
  /*********************************************************/
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
}
/****************************************/
void Forwarder::updateNeighborsList(const FaceId& faceId, const Name& name) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	size_t				pos;
	/*--------------------------*/
	osNamePrefix << name;
	namePrefix 	= osNamePrefix.str();
	//check hello interest
	pos = namePrefix.find("nlsr/INFO");
	if(pos == std::string::npos){
		return;
	}
	//NFD_LOG_INFO("updateNeighborsList: name=" << namePrefix);
	//check already exist
	std::vector<FaceId>::iterator it;
	it = std::find(m_fib.m_neighborsList.begin(), m_fib.m_neighborsList.end(), faceId);
	if(it == m_fib.m_neighborsList.end()) {
		//new neighbor, add into table
		m_fib.m_neighborsList.push_back(faceId);
		//NFD_LOG_INFO("updateNeighborsList: added faceId=" << faceId);
	}

}
void Forwarder::sendMPPTableToNeighbors() {
    ndn::Data *data = new ndn::Data();
    std::string mppInterestPrefix = "ndn:/mpp/ProudToShare";
    std::string mppTableStr = "";

	for(struct fib::M_MPPTable_Struct node: m_fib.m_MPPTable){
		mppTableStr += to_string(node.pVal) + "#" + node.name + "#";
	}
    //create a data
    data->setName(ndn::Name(mppInterestPrefix).appendVersion());
    data->setFreshnessPeriod(ndn::time::seconds(10)); // 10 sec
    NFD_LOG_INFO("sendMPPTableToNeighbors mppTableStr:" << mppTableStr);
    data->setContent((const uint8_t*)(mppTableStr.c_str()), mppTableStr.size());
    ndn::security::v2::KeyChain m_keyChain;
    m_keyChain.sign(*data);

    for(FaceId f_id: m_fib.m_neighborsList) {
        nfd::face::Face* outFace = m_faceTable.get(f_id);
        if (outFace != nullptr) {
        	//NFD_LOG_INFO("sendMPPTableToNeighbors data=" << mppInterestPrefix << " outfaceid=" << outFace->getId());
        	this->onOutgoingData(*data, *outFace);
        }
    }
}

FaceId Forwarder::findFaceIdInMMPTable(const Interest& interest ) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	size_t				pos;
	/*--------------------------*/
	osNamePrefix << interest.getName();
	namePrefix 	= osNamePrefix.str();

	for(struct fib::M_MPPTable_Struct node: m_fib.m_MPPTable){
		pos = node.name.find(namePrefix);
		if(pos != std::string::npos){
			return node.faceId;
		}
	}
	return 0;
}
void Forwarder::dumpMPPTable() {
	if(m_fib.m_MPPTable.size() > 0) {
		NFD_LOG_INFO("-----------dumpMPPTable In-----------");
		for(struct fib::M_MPPTable_Struct n: m_fib.m_MPPTable) {
			NFD_LOG_INFO("Name = " << n.name << ", inFaceId = " << n.faceId << ", pVal = " << n.pVal);
		}
		NFD_LOG_INFO("-----------dumpMPPTable Out-----------");
	}
	/*if(m_fib.m_neighborsList.size() > 0 ) {
		NFD_LOG_INFO("-----------m_neighborsList in-----------");
		for(FaceId i: m_fib.m_neighborsList) {
			NFD_LOG_INFO("Neigbor FaceId = " << i);
		}
		NFD_LOG_INFO("-----------m_neighborsList out-----------");
	}*/
}
void Forwarder::getSharedMPPTable(const FaceId& faceId, const Data& data) {
	std::ostringstream 	osNamePrefix;
	std::ostringstream 	osContentStream;
	std::string 		namePrefix, contentStrFull, h, contentString;
	std::vector<std::string> rowList;
	size_t				pos, pos2;
	Block content;
	char buf[16];
	int toggleBit, pVal = 0;
	/*--------------------------*/
	//get the segment portion from the name prefix
	osNamePrefix << data.getName();
	namePrefix 	= osNamePrefix.str();
	//check if someone is sharing its mpp table
	pos = namePrefix.find("ProudToShare");
	if(pos == std::string::npos){
		return;
	}

	//It is shared data from neighbors
	NFD_LOG_INFO("getSharedMPPTable: <ProudToShare> FaceId = " << faceId << ", Name = " << namePrefix);

	osContentStream << data.getContent();
	contentStrFull = osContentStream.str();

	NFD_LOG_INFO("getSharedMPPTable: <ProudToShare> data : " << contentStrFull);
	//find the "=" sign position
	pos2 = contentStrFull.find("=");
	if(pos2 == std::string::npos){
		NFD_LOG_INFO("addMPPStatisticTable: '=' not found");
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
	NFD_LOG_INFO("ProudToShare Data:" << contentString);
	rowList.clear();
	boost::split(rowList, contentString, boost::is_any_of("#"));
	if(rowList.size() > 0 ) {
		toggleBit = 0;
		for(std::string nPrefix: rowList) {
			if(nPrefix == "") {
				continue;
			}

			if(toggleBit == 0) {//probability
				pVal = std::stoi(nPrefix) - 1;
				toggleBit = 1;
			}
			else {//namePrefix
				NFD_LOG_INFO("save it: nPrefix:" << nPrefix << "pVal:" << pVal);
				addMPPStatisticTable(faceId, nPrefix, pVal);
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
	/*--------------------------*/
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
	addMPPStatisticTable(faceId, namePrefix, 100);

}
void Forwarder::addMPPStatisticTable(const FaceId& faceId, const std::string namePrefix, const int probability) {

	NFD_LOG_INFO("addMPPStatisticTable: FaceId = " << faceId <<", Name = " << namePrefix);
	//check the table if incoming interest already exists
	for(struct fib::M_MPPTable_Struct n: m_fib.m_MPPTable) {
		if(n.name == namePrefix) {
			if(n.pVal <= probability) {
				NFD_LOG_INFO("save in: faceId:" << faceId << "probability:" << probability);
				n.faceId = faceId;
				n.pVal 	 = probability;
				NFD_LOG_INFO("addMPPStatisticTable:Updated.");
				dumpMPPTable();
			}
			return;
		}
	}
	//otherwise create a new node
	if(m_fib.m_MPPTable.size() > 100){
		return;
	}

    try {
    	struct fib::M_MPPTable_Struct node;
    	node.name 	= namePrefix;
    	node.faceId = faceId;
    	node.pVal 	= probability;
    	m_fib.m_MPPTable.push_back(node);
    	dumpMPPTable();
    }
    catch (std::bad_alloc& ba) {
    	NFD_LOG_DEBUG("addMPPStatisticTable: bad_alloc error.");
    	return;
    }

    NFD_LOG_INFO("addMPPStatisticTable: New Entry.");
    //advertise the mpp table
    sendMPPTableToNeighbors();
}
//PIT entries for the data segments coming producer
void Forwarder::addInterestCacheTable(const FaceId& faceId, const Name& name){
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::string 		segment_str;
	std::string			newPrefix;
	size_t				pos;
	/*--------------------------*/
	/*remove the expired records*/
	/*--------------------------*/
	for(unsigned int i = 0; i < m_fib.m_CacheTable.size(); i++) {
		if(std::abs(m_fib.m_CacheTable[i].updateTime - std::time(0)) > 600){ //10min
			m_fib.m_CacheTable.erase(m_fib.m_CacheTable.begin() + i);
		}
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
		NFD_LOG_DEBUG("addInterestCacheTable: Error npos");
		return;
	}
	//check is valid segment
	segment_str = namePrefix.substr(pos);
	if(segment_str.length() != 7) {
		NFD_LOG_DEBUG("addInterestCacheTable: Error sizeLessThan7");
		return;
	}
	//buffer{segment_str.substr(5,5)}; buffer >> hex >> segment_no;
	newPrefix = namePrefix.substr(0, pos + 4);
	//Everything is okay, now add the name into table
	NFD_LOG_INFO("addInterestCacheTable: <inTable> FaceId = " << faceId <<", Name = " << name);
	//check the table if incoming interest already exists
	for(struct fib::M_CacheTable_Struct n: m_fib.m_CacheTable) {
		if(!n.name.compare(newPrefix)) {
			n.faceIdList.push_back(faceId);
			NFD_LOG_INFO("addInterestCacheTable:Update.");
			return;
		}
	}
	//otherwise create a new node
    try {
    	struct fib::M_CacheTable_Struct node;
    	node.name 		= newPrefix;
    	node.faceIdList.push_back(faceId);
    	node.updateTime = std::time(0); //timestamp for record deletiton
    	m_fib.m_CacheTable.push_back(node);
    }
    catch (std::bad_alloc& ba) {
    	NFD_LOG_DEBUG("addInterestCacheTable: bad_alloc error.");
    	return;
    }

    NFD_LOG_INFO("addInterestCacheTable: New Entry.");
}
/*Find the list of the requester for the original data and send the rest of the segments*/
bool Forwarder::forwardDataSegments(const Data& data) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::string 		segment_str;
	std::string			newPrefix;
	size_t				pos;
	int					segment_no = 0;
	//get the segment portion from the name prefix
	try {
		osNamePrefix << data.getName();
		namePrefix 	= osNamePrefix.str();
		pos 		= namePrefix.find("/%00");
		if(pos == std::string::npos) {
			NFD_LOG_DEBUG("forwardDataSegments: Error up_npos");
			return false;
		}
		//check is valid segment
		segment_str = namePrefix.substr(pos);
		if(segment_str.length() != 7) {
			NFD_LOG_DEBUG("forwardDataSegments: Error up_sizeLessThan7");
			return false;
		}
		newPrefix = namePrefix.substr(0, pos + 4);
		for(struct fib::M_CacheTable_Struct node: m_fib.m_CacheTable) {
			if(!node.name.compare(newPrefix)) {
				//update timestamp for this node
				node.updateTime = std::time(0);
				//check segment no
				segment_no = std::stoi(segment_str.substr(5,5), 0 , 16);
				if(std::find(node.segmentUpList.begin(), node.segmentUpList.end(), segment_no) != node.segmentUpList.end() ) {
					NFD_LOG_INFO("forwardDataSegments: Already Sent: segment_no = " << segment_no);
					return false;
				}
				NFD_LOG_INFO("forwardDataSegments: <popMatch> data name = " << data.getName());
				for(FaceId fid: node.faceIdList) {
					Face *outFace = m_faceTable.get(fid);
					//send the data to the outputstream
					outFace->sendData(data);
					NFD_LOG_INFO("forwardDataSegments:Forwarded FaceId = " << fid);
				}
				node.segmentUpList.push_back(segment_no);
				return true;
			}
		}
	}
	catch(std::exception e) {
		//do nothing
	}

	NFD_LOG_DEBUG("forwardDataSegments: No match.");
	return false;
}

void Forwarder::sendOtherDataSegments(Face& outFace, const Data& data) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::string 		segment_str;
	std::string			newPrefix;
	std::string			keyPrefix;
	size_t				pos;
	int					segment_no = 0;
	std::vector<ndn::Data> segDataList;
	//get the segment portion from the name prefix
	try {
		osNamePrefix << data.getName();
		namePrefix 	= osNamePrefix.str();
		pos 		= namePrefix.find("/%00");
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
		newPrefix = namePrefix.substr(0, pos + 4);
		//get segment no
		segment_no = std::stoi(segment_str.substr(5,5), 0 , 16);
		//check the CS for the next segment
		m_cs.checkContentStoreTable(segDataList, newPrefix, segment_no);
		for(ndn::Data seg_data: segDataList) {
			//send to outFace
			NFD_LOG_INFO("sendOtherDataSegments: <seg_hit> name = " << seg_data.getName());
			outFace.sendData(seg_data);//send
		}
	}
	catch(std::exception e) {
		//do nothing
	}
}

void Forwarder::sendRelativeDatas(Face& inFace, const Name& name){
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::vector<std::string> vPrefix;
	std::vector<ndn::Data> v_RelativeData;
	size_t				pos;
	//get the segment portion from the name prefix
	try {
		osNamePrefix << name;
		namePrefix 	= osNamePrefix.str();
		//check black name list prefix
		for(std::string l: nameBlackList){
			pos = namePrefix.find(l);
			if(pos != std::string::npos){
				return;
			}
		}
		boost::split(vPrefix, namePrefix, boost::is_any_of("/"));
		//get relative datas from the content store
		m_cs.getRelativeDatas(vPrefix, v_RelativeData);

		if(v_RelativeData.size() > 0 ) {
			NFD_LOG_INFO("sendRelativeDatas: <parent_int> name = " << namePrefix);
		}
		for(ndn::Data rdata: v_RelativeData) {
			//send to outFace
			NFD_LOG_INFO("sendRelativeDatas: <relative_hit> name = " << rdata.getName());
			inFace.sendData(rdata);//send
		}
	}
	catch(std::exception e) {
		//do nothing
	}


}

void Forwarder::dumpCacheTable() {
	NFD_LOG_DEBUG("-----------dumpCacheTable In-----------");
	for(struct fib::M_CacheTable_Struct n: m_fib.m_CacheTable) {
		for(FaceId i: n.faceIdList) {
			NFD_LOG_DEBUG("Name = " << n.name << ", inFaceId = " << i);
		}
	}
	NFD_LOG_DEBUG("-----------dumpCacheTable Out-----------");
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
	NFD_LOG_INFO("onIncomingData face=" << inFace.getId() << " data=" << data.getName());
  data.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInData;
  updateNeighborsList(inFace.getId(), data.getName());
  getSharedMPPTable(inFace.getId(), data);
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
    this->onDataUnsolicited(inFace, data);
    return;
  }

  // CS insert
  m_cs.insert(data);
  // when only one PIT entry is matched, trigger strategy: after receive Data
  if (pitMatches.size() == 1) {
    auto& pitEntry = pitMatches.front();

    NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());

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
    }
  }
  //statistic table
  addMPPStatisticTable(inFace.getId(), data);//populate table
}

void
Forwarder::onDataUnsolicited(Face& inFace, const Data& data)
{
  bool isDataNotCached;
  isDataNotCached = true;
  // accept to cache?
  fw::UnsolicitedDataDecision decision = m_unsolicitedDataPolicy->decide(inFace, data);
  if (decision == fw::UnsolicitedDataDecision::CACHE) {
    // CS insert
    m_cs.insert(data, true);

    isDataNotCached = false;
  }

  /*if(forwardDataSegments(data) && isDataNotCached) { //send the data to upstream
	  m_cs.insert(data, true);
  }*/
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
  sendOtherDataSegments(outFace, data);
}

void
Forwarder::onIncomingNack(Face& inFace, const lp::Nack& nack)
{
  // receive Nack
  nack.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInNacks;

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
