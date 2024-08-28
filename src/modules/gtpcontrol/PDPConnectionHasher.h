/*
 * PDPConnectionHasher.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PDP_CONNECTION_HASHER_H__
#define __PDP_CONNECTION_HASHER_H__

#include <cassert>

#include "PDPConnection.h"

/**
 * Helper class for generating hash value for a PDPConnection object.
 */
class PDPConnectionHasher
{
    public:
        /**
         * Returns a hash value for the given PDPConnection object.
         *
         * @param p the PDPConnection
         *
         * @return the hash value
         */
        size_t operator()(const PDPConnection* p) const;
};

inline size_t
PDPConnectionHasher::operator()(const PDPConnection* p) const
{
    assert(p != 0);
    
    return static_cast<size_t>(p->_teid + p->_ipTeidOwner->hashValue());
}

#endif // __GTP_CONNECTION_HASHER_H__
