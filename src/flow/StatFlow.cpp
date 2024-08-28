/*
 * StatFlow.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "StatFlow.h"

CAPTOOL_POOLABLE_INIT_POOL(StatFlow, 10000)

void
StatFlow::packet(const struct timeval *timestamp, bool upload, unsigned long length)
{
    iat = timestamp->tv_sec - _lastPacket.tv_sec + (timestamp->tv_usec - _lastPacket.tv_usec) / 1e6;
    if (_statistics != NULL)
    {
        _statistics->packet(timestamp, upload, length);
    }
    
    BasicFlow::packet(timestamp, upload, length);
};

std::ostream& 
operator<<(std::ostream& o, const StatFlow& flow)
{
    o << (BasicFlow&)flow;
    if (flow._statistics != NULL)
    {
        o << "|" << *(flow._statistics);
    }
    
    return o;
}

void
StatFlow::enableDetailedStatistics()
{
    if (_statistics == NULL)
    {
        _statistics = new PacketStatistics();
    }
}

