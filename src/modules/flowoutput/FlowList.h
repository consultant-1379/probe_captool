/*
 * FlowList.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_LIST_H__
#define __FLOW_LIST_H__

#include <boost/shared_ptr.hpp>
#include <boost/function.hpp>
#include <set>
#include <utility>
#include <functional>
#include <tr1/functional> // std::hash
#include <ctime>
#include "flow/FlowID.h"
#include "flow/FlowIDHasher.h"
#include "util/TimeSortedList.h"

namespace captool {

/**
 * Template for storing flowID-to-flow map and time-sorted list of flow structures.
 */
template<class FlowType, class FlowIDComparator>
class FlowList : public TimeSortedList<FlowID::Ptr, FlowType, std::tr1::hash<const FlowID::Ptr>, FlowIDComparator> {
    
    public:
        
        FlowList();
        
        /**
         * Move flow to the end of the list. Appends flow if not already in the list.
         * Does nothing either if ''flow'' points to a null structure or it has no flow ID.
         */
        void moveToEnd(const boost::shared_ptr<FlowType> flow);
        
        /**
         * Add new <flowID,flow*> pair to the map, and make it the last flow in the list.
         */
        void insert(FlowID::Ptr, const boost::shared_ptr<FlowType>);
};

template <class F, class C>
FlowList<F,C>::FlowList()
  : TimeSortedList<FlowID::Ptr,F,std::tr1::hash<const FlowID::Ptr>,C>()
{
}

template <class F, class C>
inline void
FlowList<F,C>::insert(FlowID::Ptr flowid, const boost::shared_ptr<F> flow)
{
    if (! flowid) return;
    
    TimeSortedList<FlowID::Ptr,F,std::tr1::hash<const FlowID::Ptr>,C>::insert(flowid, flow);
}

template <class F, class C>
void
FlowList<F,C>::moveToEnd(const boost::shared_ptr<F> flow)
{
    if ((! flow) || (! flow->getID())) return;
    
    boost::shared_ptr<F> flowptr = get(flow->getID());
    
    if (! flowptr)
        insert(flow->getID(), flow);
    else
        TimeSortedList<FlowID::Ptr,F,std::tr1::hash<const FlowID::Ptr>,C>::moveToEnd(flowptr->getID());
}

} // namespace captool

#endif // __FLOW_LIST_H__
