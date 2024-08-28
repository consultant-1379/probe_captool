/*
 * FlowIDEqualsStrict.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_ID_EQUALS_STRICT_H__
#define __FLOW_ID_EQUALS_STRICT_H__

#include <cassert>

#include "FlowID.h"

/**
 * Helper class for comparing two FlowID objects. Unlike FlowIDEquals, this class provides strict comparison:
 * FlowIDs with swapped source and destination fields are considered different.
 */
class FlowIDEqualsStrict
{
    public:
        
        /**
         * Compares two FlowID objects.
         *
         * @param fidA a FlowID object
         * @param fidB a FlowID object
         *
         * @return true if the two FlowID objects represent the same connection
         */
        bool operator()(const FlowID::Ptr fidA, const FlowID::Ptr fidB) const;
};

inline bool
FlowIDEqualsStrict::operator()(const FlowID::Ptr fidA, const FlowID::Ptr fidB) const
{
    assert(fidA.get() != 0);
    assert(fidB.get() != 0);
    
    assert(fidA->_srcIP != 0);
    assert(fidA->_dstIP != 0);
    assert(fidB->_srcIP != 0);
    assert(fidB->_dstIP != 0);
    
    if (fidA.get() == fidB.get())
    {
        return true;
    }

    return (
        fidA->_protocol == fidB->_protocol &&
        fidA->_srcPort  == fidB->_srcPort  &&
        fidA->_dstPort  == fidB->_dstPort  &&
        fidA->_srcIP->equals(fidB->_srcIP) &&
        fidA->_dstIP->equals(fidB->_dstIP)
    );
}

#endif // __FLOW_ID_EQUALS_STRICT_H__
