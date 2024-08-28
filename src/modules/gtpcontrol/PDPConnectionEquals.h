/*
 * PDPConnectionEquals.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PDP_CONNECTION_EQUALS_H__
#define __PDP_CONNECTION_EQUALS_H__

#include <cassert>

#include "PDPConnection.h"

/**
 * Helper class for comparing two PDPConnection objects.
 */
class PDPConnectionEquals
{
    public:
        
        /**
         * Compares two PDPConnection objects.
         *
         * @param a a PDPConnection object
         * @param b a PDPConnection object
         *
         * @return true if the two PDPConnection objects represent the same connection
         */
        bool operator()(const PDPConnection* a, const PDPConnection* b) const;
};

inline bool
PDPConnectionEquals::operator()(const PDPConnection *a, const PDPConnection *b) const
{
    assert(a != 0);
    assert(b != 0);
    
    return a->equals(b);
};

#endif // __PDP_CONNECTION_EQUALS_H__
