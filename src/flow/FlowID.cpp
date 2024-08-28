/*
 * FlowID.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "FlowID.h"
#include "ip/IPAddress.h"

CAPTOOL_POOLABLE_INIT_POOL(FlowID, 300000)

std::ostream& operator<<(std::ostream& o, const FlowID& id)
{
    o << FlowID::ipProtocolToString(id._protocol);
    o << "|";
    if (id._srcIP == 0)
    {
        o << "na";
    }
    else
    {
        o << *(id._srcIP);
    }
    o << "|";
    if (id._protocol == IPPROTO_TCP || id._protocol == IPPROTO_UDP)
    {
        o << ntohs(id._srcPort);
    }
    else
    {
        o << "na";
    }
    o << "|";
    if (id._dstIP == 0)
    {
        o << "na";
    }
    else
    {
        o << *(id._dstIP);
    }
    o << "|";
    if (id._protocol == IPPROTO_TCP || id._protocol == IPPROTO_UDP)
    {
        o << ntohs(id._dstPort);
    }
    else
    {
        o << "na";
    }
    return o;
}

string 
FlowID::ipProtocolToString(u_int8_t protocol)
{
    switch (protocol)
    {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_IPV6: return "IPv6";
        case IPPROTO_GRE: return "GRE";
        case IPPROTO_ESP: return "ESP";
        default: std::ostringstream s; s << (unsigned)protocol; return s.str();
    }
}


namespace std { namespace tr1 {

template<>
std::size_t
hash<const FlowID::Ptr>::operator() (const FlowID::Ptr fid)
const
{
    return fid.get() ? 
      (size_t)( (fid->getSourceIP()->hashValue() ^ fid->getDestinationIP()->hashValue()) + (fid->getSourcePort() ^ fid->getDestinationPort()) - fid->getProtocol() )
      : 0;
}

}} // std::tr1::
