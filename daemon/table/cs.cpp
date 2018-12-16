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

#include "cs.hpp"
#include "core/algorithm.hpp"
#include "core/logger.hpp"

#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/util/concepts.hpp>

namespace nfd {
namespace cs {

NDN_CXX_ASSERT_FORWARD_ITERATOR(Cs::const_iterator);

NFD_LOG_INIT(ContentStore);

static unique_ptr<Policy>
makeDefaultPolicy()
{
  return Policy::create("lru");
}

Cs::Cs(size_t nMaxPackets)
  : m_shouldAdmit(true)
  , m_shouldServe(true)
{
  this->setPolicyImpl(makeDefaultPolicy());
  m_policy->setLimit(nMaxPackets);
}

void
Cs::insert(const Data& data, bool isUnsolicited)
{
  if (!m_shouldAdmit || m_policy->getLimit() == 0) {
    return;
  }
  NFD_LOG_DEBUG("insert " << data.getName());

  // recognize CachePolicy
  shared_ptr<lp::CachePolicyTag> tag = data.getTag<lp::CachePolicyTag>();
  if (tag != nullptr) {
    lp::CachePolicyType policy = tag->get().getPolicy();
    if (policy == lp::CachePolicyType::NO_CACHE) {
      return;
    }
  }

  iterator it;
  bool isNewEntry = false;
  std::tie(it, isNewEntry) = m_table.emplace(data.shared_from_this(), isUnsolicited);
  EntryImpl& entry = const_cast<EntryImpl&>(*it);

  entry.updateStaleTime();

  if (!isNewEntry) { // existing entry
    // XXX This doesn't forbid unsolicited Data from refreshing a solicited entry.
    if (entry.isUnsolicited() && !isUnsolicited) {
      entry.unsetUnsolicited();
    }

    m_policy->afterRefresh(it);
  }
  else {
    m_policy->afterInsert(it);
  }
}

void
Cs::erase(const Name& prefix, size_t limit, const AfterEraseCallback& cb)
{
  BOOST_ASSERT(static_cast<bool>(cb));

  iterator first = m_table.lower_bound(prefix);
  iterator last = m_table.end();
  if (prefix.size() > 0) {
    last = m_table.lower_bound(prefix.getSuccessor());
  }

  size_t nErased = 0;
  while (first != last && nErased < limit) {
    m_policy->beforeErase(first);
    first = m_table.erase(first);
    ++nErased;
  }

  if (cb) {
    cb(nErased);
  }
}

void
Cs::find(const Interest& interest,
         const HitCallback& hitCallback,
         const MissCallback& missCallback) const
{
  BOOST_ASSERT(static_cast<bool>(hitCallback));
  BOOST_ASSERT(static_cast<bool>(missCallback));

  if (!m_shouldServe || m_policy->getLimit() == 0) {
    missCallback(interest);
    return;
  }
  const Name& prefix = interest.getName();
  bool isRightmost = interest.getChildSelector() == 1;
  NFD_LOG_DEBUG("find " << prefix << (isRightmost ? " R" : " L"));

  iterator first = m_table.lower_bound(prefix);
  iterator last = m_table.end();
  if (prefix.size() > 0) {
    last = m_table.lower_bound(prefix.getSuccessor());
  }

  iterator match = last;
  if (isRightmost) {
    match = this->findRightmost(interest, first, last);
  }
  else {
    match = this->findLeftmost(interest, first, last);
  }

  if (match == last) {
    NFD_LOG_DEBUG("  no-match");
    missCallback(interest);
    return;
  }
  NFD_LOG_DEBUG("  matching " << match->getName());
  m_policy->beforeUse(match);
  hitCallback(interest, match->getData());
}

iterator
Cs::findLeftmost(const Interest& interest, iterator first, iterator last) const
{
  return std::find_if(first, last, [&interest] (const auto& entry) { return entry.canSatisfy(interest); });
}

iterator
Cs::findRightmost(const Interest& interest, iterator first, iterator last) const
{
  // Each loop visits a sub-namespace under a prefix one component longer than Interest Name.
  // If there is a match in that sub-namespace, the leftmost match is returned;
  // otherwise, loop continues.

  size_t interestNameLength = interest.getName().size();
  for (iterator right = last; right != first;) {
    iterator prev = std::prev(right);

    // special case: [first,prev] have exact Names
    if (prev->getName().size() == interestNameLength) {
      NFD_LOG_TRACE("  find-among-exact " << prev->getName());
      iterator matchExact = this->findRightmostAmongExact(interest, first, right);
      return matchExact == right ? last : matchExact;
    }

    Name prefix = prev->getName().getPrefix(interestNameLength + 1);
    iterator left = m_table.lower_bound(prefix);

    // normal case: [left,right) are under one-component-longer prefix
    NFD_LOG_TRACE("  find-under-prefix " << prefix);
    iterator match = this->findLeftmost(interest, left, right);
    if (match != right) {
      return match;
    }
    right = left;
  }
  return last;
}

iterator
Cs::findRightmostAmongExact(const Interest& interest, iterator first, iterator last) const
{
  return find_last_if(first, last, [&interest] (const auto& entry) { return entry.canSatisfy(interest); });
}

void
Cs::dump()
{
  NFD_LOG_DEBUG("dump table");
  for (const EntryImpl& entry : m_table) {
    NFD_LOG_TRACE(entry.getFullName());
  }
}
/****************************************/
bool
Cs::checkContentStoreTable(std::vector<ndn::Data> &vdata, std::string key, int in_seg_no) {
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	std::string 		segment_str;
	size_t				pos;
	int segment_no = 0,wc = 0;
	//get the segment portion from the name prefix
	try {
		for (const EntryImpl& entry : m_table) {
			osNamePrefix << entry.getData().getName();
			namePrefix 	= osNamePrefix.str();
			wc = matchingChar(key, namePrefix);
			if(wc == key.length()) {//match
				//check segment no
				pos = namePrefix.find("/%00");
				if(pos == std::string::npos) {
					continue;
				}
				//check is valid segment
				segment_str = namePrefix.substr(pos);
				if(segment_str.length() != 7) {
					continue;
				}
				//get segment no
				segment_no = std::stoi(segment_str.substr(5,5), 0 , 16);
				if(in_seg_no != segment_no) {
					vdata.push_back(entry.getData());
				}
			}
		}
	}
	catch(std::exception e) {
		//do nothing
	}
	return false;
}
void
Cs::getRelativeDatas(std::vector<std::string> vIntNameList, std::vector<ndn::Data> &vdata){
	std::ostringstream 	osNamePrefix;
	std::string 		namePrefix;
	int wc = 0, total = 0, counter = 0;
	//get the segment portion from the name prefix
	try {
		counter = 0;
		for (const EntryImpl& entry : m_table) {
			osNamePrefix << entry.getData().getName();
			namePrefix 	= osNamePrefix.str();
			total = 0; //clear total for name
			for(std::string i: vIntNameList) {
				wc = matchingChar(i, namePrefix);
				if(wc == i.length()){
					total++;
				}
				else {
					break;
				}
			}
			if(total > 2) {
				vdata.push_back(entry.getData());
			}
			if(counter++ > 2) {
				break;
			}
		}

	}
	catch(std::exception e) {
		//do nothing
	}
}

int
Cs::matchingChar(std::string const &s1, std::string const &s2) {
	int s1_freq[256] = {};
	int s2_freq[256] = {};
	std::for_each(std::begin(s1), std::end(s1), [&](unsigned char c) {++s1_freq[c];});
	std::for_each(std::begin(s2), std::end(s2), [&](unsigned char c) {++s2_freq[c];});
	return std::inner_product(std::begin(s1_freq), std::end(s1_freq), std::begin(s2_freq), 0, std::plus<>(),
								[](auto l, auto r) {return std::min(l, r); });
}
/****************************************/
void
Cs::setPolicy(unique_ptr<Policy> policy)
{
  BOOST_ASSERT(policy != nullptr);
  BOOST_ASSERT(m_policy != nullptr);
  size_t limit = m_policy->getLimit();
  this->setPolicyImpl(std::move(policy));
  m_policy->setLimit(limit);
}

void
Cs::setPolicyImpl(unique_ptr<Policy> policy)
{
  NFD_LOG_DEBUG("set-policy " << policy->getName());
  m_policy = std::move(policy);
  m_beforeEvictConnection = m_policy->beforeEvict.connect([this] (iterator it) {
      m_table.erase(it);
    });

  m_policy->setCs(this);
  BOOST_ASSERT(m_policy->getCs() == this);
}

void
Cs::enableAdmit(bool shouldAdmit)
{
  if (m_shouldAdmit == shouldAdmit) {
    return;
  }
  m_shouldAdmit = shouldAdmit;
  NFD_LOG_INFO((shouldAdmit ? "Enabling" : "Disabling") << " Data admittance");
}

void
Cs::enableServe(bool shouldServe)
{
  if (m_shouldServe == shouldServe) {
    return;
  }
  m_shouldServe = shouldServe;
  NFD_LOG_INFO((shouldServe ? "Enabling" : "Disabling") << " Data serving");
}

} // namespace cs
} // namespace nfd
