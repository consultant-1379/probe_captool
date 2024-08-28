/*
 * IPFragmentHole.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IP_FRAGMENT_HOLE_H__
#define __IP_FRAGMENT_HOLE_H__

#include <cassert>

#include <sys/types.h>
#include <climits>

#include "util/poolable.h"

/**
 * Represents an IP Fragment hole
 *
 * @note see RFC815
 * @note IPFragmentHole._last = RFC815._last + 1
 */
class IPFragmentHole
{
    public:
        
        /** 
         * Constructor
         *
         * @param first location of the first byte of this hole
         * @param last location of the byte after the last byte of this hole
         */
        IPFragmentHole(u_int first, u_int last);

        CAPTOOL_POOLABLE_DECLARE_METHODS()
    private:
        
        /** location of the first byte of this hole */
        u_int _first;
        
        /** location of the byte after the last byte of this hole */
        u_int _last;
        
        /** represents infinity for last in holes */
        static const u_int MAX_END = UINT_MAX;
        
        friend class IPFragments;

        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(IPFragmentHole)

inline
IPFragmentHole::IPFragmentHole(u_int first, u_int last)
    : _first(first),
      _last(last)
{
}

#endif // __IP_FRAGMENT_HOLE_H__
