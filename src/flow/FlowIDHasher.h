/*
 * FlowIDHasher.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_ID_HASHER_H__
#define __FLOW_ID_HASHER_H__

#include <cassert>

#include "FlowID.h"

/**
 * Helper class for generating hash value for a FlowID object.
 */
class FlowIDHasher
{
    public:
        
        /**
         * Returns a hash value for the given FlowID object.
         *
         * @param fid the FlowID
         *
         * @return the hash value
         */
        size_t operator()(const FlowID* fid) const;
};

inline size_t
FlowIDHasher::operator()(const FlowID* fid) const
{
    assert(fid != 0);
    
    return (size_t)( (fid->_srcIP->hashValue() ^ fid->_dstIP->hashValue()) + (fid->_srcPort ^ fid->_dstPort) - fid->_protocol);
}

#endif // __FLOW_ID_HASHER_H__
