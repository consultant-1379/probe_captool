/*
 * IPAddress.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "IPAddress.h"

CAPTOOL_POOLABLE_INIT_POOL(IPAddress, 100000)

std::ostream& operator<< (std::ostream& o, const IPAddress& ip)
{
    switch (ip._type)
    {
        case (IPAddress::IPv4) :
        {
            u_int8_t *a = (u_int8_t*) & ip._addr;
            return o << (u_int) a[0]  << "." << (u_int) a[1]  << "." << (ip._trunc ? (u_int) 0 : (u_int) a[2])  << "." << (ip._trunc ? (u_int) 0 : (u_int) a[3]);
        }
        case (IPAddress::IPv6) :
        {
            return o << "(IPv6 address)";
        }
        default:
            return o << "(IPv? address)";
    }
}

std::ostream&
operator<< (std::ostream& o, const IPAddress::Ptr& ip)
{
    if (ip)
        o << *(ip.get());
    else
        o << "na";
    return o;
}

namespace std {

template<>
bool
equal_to<const IPAddress::Ptr>::operator() (const IPAddress::Ptr & x, const IPAddress::Ptr & y)
const
{
    if (x.get() == y.get())
        return true;
    
    if (x)
        return x->equals(y);
    
    return false;
}

namespace tr1 {

template<>
std::size_t
hash<const IPAddress::Ptr>::operator() (const IPAddress::Ptr ip)
const
{
    return ip ? ip->hashValue() : 0;
}

}} // std::tr1::
