/*
 * MACAddress.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __MACADDRESS_H__
#define __MACADDRESS_H__

#include <boost/shared_ptr.hpp>
#include <string>
#include <cstring>
#include <ostream>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <tr1/functional> // hash

#include "util/poolable.h"
#include "ID.h"

class MACAddressException
{
};

/**
 * Class representing an Ethernet hardware address.
 */
class MACAddress : public ID
{
    public:
        /** Pointer type for safe exchange of MAC address pointers */
        typedef boost::shared_ptr<MACAddress> Ptr;

        /**
         * Constructor for Ethernet hardware address.
         *
         * @param addr the raw address in network byte order
         */
        MACAddress (uint8_t * const& addr);
        
        /**
         * Constructor for Ethernet address.
         *
         * @param addr the ascii representation of the ethernet address
         */
        MACAddress (const std::string &) throw (MACAddressException);
        
        /**
         * Destructor.
         */
        ~MACAddress();
        
        /**
         * Checks whether the address is a broadcast MAC address
         *
         * @return true if the address is ff:ff:ff:ff:ff:ff
         */
        bool isBroadcast() const;
        
        /**
         * Checks whether the address is a broadcast MAC address
         *
         * @return true if the address is ff:ff:ff:ff:ff:ff
         */
        static bool isBroadcast (uint8_t * const&);//const struct ether_addr * addr);
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()
        
    protected:
        /**
         * Generate ASCII transcript of the Ethernet hardware address.
         */
        void mkstring();
        
    private:

        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(MACAddress)

std::ostream& operator<<(std::ostream&, const MACAddress::Ptr&);

bool operator== (const MACAddress::Ptr&, const MACAddress::Ptr&);
bool operator!= (const MACAddress::Ptr&, const MACAddress::Ptr&);

namespace std { namespace tr1 {
    template<> std::size_t hash<MACAddress::Ptr>::operator() (MACAddress::Ptr) const;
}}

#endif
