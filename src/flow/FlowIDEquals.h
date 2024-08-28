/*
 * FlowIDEquals.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_ID_EQUALS_H__
#define __FLOW_ID_EQUALS_H__

#include <cassert>

#include "FlowID.h"

/**
 * Helper class for comparing two FlowID objects.
 */
class FlowIDEquals
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
FlowIDEquals::operator()(const FlowID::Ptr fidA, const FlowID::Ptr fidB) const
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
        //fidA and fidB points to the same direction
        (
            fidA->_protocol == fidB->_protocol &&
            fidA->_srcPort  == fidB->_srcPort  &&
            fidA->_dstPort  == fidB->_dstPort  &&
            fidA->_srcIP->equals(fidB->_srcIP) &&
            fidA->_dstIP->equals(fidB->_dstIP)
        )
        ||
        //fidA and fidB points to the same direction
        (
            fidA->_protocol == fidB->_protocol &&
            fidA->_srcPort  == fidB->_dstPort  &&
            fidA->_dstPort  == fidB->_srcPort  &&
            fidA->_srcIP->equals(fidB->_dstIP) &&
            fidA->_dstIP->equals(fidB->_srcIP)
        )
    );
}

#endif // __FLOW_ID_EQUALS_H__
