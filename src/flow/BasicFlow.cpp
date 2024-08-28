/*
 * BasicFlow.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "BasicFlow.h"
#include <iomanip>

CAPTOOL_POOLABLE_INIT_POOL(BasicFlow, 10000)
        
std::ostream&
operator<<(std::ostream& o, const BasicFlow& flow)
{
    o << std::setfill('0') << flow._firstPacket.tv_sec << "." << std::setw(6) << flow._firstPacket.tv_usec << std::setw(0)
      << "|" << flow._lastPacket.tv_sec << "." << std::setw(6) << flow._lastPacket.tv_usec << std::setw(0)
      << "|";
    if (flow._id) o << * flow._id;
    else o << "na";
    return o << "|" << flow._uploadPackets << "|" << flow._downloadPackets << "|" << flow._uploadBytes << "|" << flow._downloadBytes;
}
