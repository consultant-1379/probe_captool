/*
 * MACAddress.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "MACAddress.h"

CAPTOOL_POOLABLE_INIT_POOL(MACAddress, 100000)

MACAddress::MACAddress(uint8_t* const& addr)
  : ID (addr, ETH_ALEN)
{
    mkstring();
}

/*
MACAddress::MACAddress(uint8_t * addr)
{
    memcpy(_addr.ether_addr_octet, addr, ETH_ALEN);
}
*/

MACAddress::~MACAddress()
{
}
    
MACAddress::MACAddress(const std::string & s) throw(MACAddressException)
  : ID (0, ETH_ALEN)
{
    struct ether_addr addr;
    if (ether_aton_r(s.c_str(), &addr) == 0)
    {
        throw MACAddressException();
    }
    bytes = new uint8_t [length];
    std::memcpy((void*) bytes, (void*) addr.ether_addr_octet, length);
    mkhash();
    mkstring();    
}

bool
MACAddress::isBroadcast() const
{
    return isBroadcast(bytes);
}

void
MACAddress::mkstring ()
{
    char buf [ETH_ALEN * 2 + 5 + 1];
    ether_ntoa_r(reinterpret_cast<struct ether_addr*>(bytes), buf); // ugly but works until array is first member of ether_addr
    strrep = buf;
}

bool
MACAddress::isBroadcast(uint8_t* const& addr)//const struct ether_addr * addr)
{
    return  addr &&
            addr[0] == 0xff &&
            addr[1] == 0xff &&
            addr[2] == 0xff &&
            addr[3] == 0xff &&
            addr[4] == 0xff &&
            addr[5] == 0xff;
//            addr->ether_addr_octet[5] == 0xff;
}

std::ostream&
operator<<(std::ostream& o, const MACAddress::Ptr& eth)
{
    return o <<  static_cast<const ID::Ptr&>(eth);
}

bool 
operator== (const MACAddress::Ptr& a, const MACAddress::Ptr& b)
{
    if (!a && !b)
        return true;
    return a ? a->operator==(*b.get()) : false;   
}       
 
bool
operator!= (const MACAddress::Ptr& a, const MACAddress::Ptr& b)
{
    return ! (a == b);
}

namespace std { namespace tr1 {

template<>
std::size_t
hash<MACAddress::Ptr>::operator() (MACAddress::Ptr mac)
const
{
    return mac ? mac->hashValue() : 0;
}

}} // std::tr1::
