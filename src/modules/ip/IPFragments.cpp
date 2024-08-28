/*
 * IPFragments.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include "util/log.h"

#include "sys/types.h"

#include "IPFragments.h"

IPFragments::IPFragments()
    : _payload(IP_FRAGMENTS_ALLOC_LENGTH)
{
}

IPFragments::~IPFragments()
{
    emptyHoles();
}

void
IPFragments::initialize(const struct timeval *timestamp)
{
    assert(timestamp != 0);
    
    _timestamp = *timestamp;

    _totalLength = 0;
    emptyHoles();

    _holes.push_back(new IPFragmentHole(0, IPFragmentHole::MAX_END));
};

void
IPFragments::addFragment(const u_char *payload, u_int first, u_int length, bool moreFrags)
{
    assert(payload != 0);
    
    // copy fragment to its position
    if (! _payload.copy(payload, first, length))
        return;
   
    u_int last = first + length;

    if (!moreFrags)
    {
        _totalLength = last;
    }
    
    // remove holes that are filled by this fragment
    for (HolesList::iterator iter(_holes.begin()), end(_holes.end()); iter != end; )
    {
        IPFragmentHole *hole = (IPFragmentHole *)(*iter);
        ++iter;
        
        // no interaction with this hole
        if (first > hole->_last || last < hole->_first)
        {
            continue;
        }

        if (first > hole->_first)
        {
            IPFragmentHole *newHole = new IPFragmentHole(hole->_first, first);
            _holes.push_front(newHole);
        }
        
        if ( (last < hole->_last) && moreFrags)
        {
            IPFragmentHole *newHole = new IPFragmentHole(last, hole->_last);
            _holes.push_front(newHole);
        }
        
        _holes.remove(hole);
        delete(hole);
    }
}

void
IPFragments::emptyHoles()
{
    //segmentation fault when make profile
    //for_each(_holes.begin(), _holes.end(), deleteHole);
    for (HolesList::const_iterator iter(_holes.begin()), end(_holes.end()); iter != end; ++iter)
    {
        delete (*iter);
    }
    _holes.clear();
}

void
IPFragments::deleteHole(IPFragmentHole *hole)
{
    assert(hole != 0);
    
    delete(hole);
}
