/*
 * IPAddress.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IP_ADDRESS_H__
#define __IP_ADDRESS_H__

#include <cassert>
#include <ctime>
#include <string>
#include <ostream>
#include <sys/types.h>
#include <boost/intrusive_ptr.hpp>
#include "util/poolable.h"
#include <functional> // equal_to
#include <tr1/functional> // hash
#include "util/RefCounter.h"

class FlowID;

/**
 * Class representing an IP address.
 * @note Currently IPv4 only although some effort was made to facilitate for
 *       v6 adderses too.
 */
class IPAddress : public RefCounter
{
    public:

        /**
         * Possible types of the IP address
         */
        enum Type {
            IPv4,   /**< IPv4 address */
            IPv6    /**< IPv6 address */
        };
        
        /** Pointer type for safe exchange of flow pointers */
        typedef boost::intrusive_ptr<IPAddress> Ptr;
        
        /**
         * Constructor for IPv4 address.
         *
         * @param addr the raw address in network byte order
         * @param truncate show only first two bytes in string representation
         */
        IPAddress (u_int32_t addr, bool truncate = false);
        
        /**
         * Destructor.
         */
        ~IPAddress();
        
        /**
         * Returns a hash value of the IP Address.
         *
         * @return hash value
         */
        std::size_t hashValue() const;
        
        /**
         * Compares the IP address to the given one.
         *
         * @param addr the address to be compared to
         *
         * @return true if the two IP addresses are equal
         */
        bool equals(const IPAddress::Ptr & addr) const;
        
        /**
         * Returns the type of the IP address
         *
         * @return type
         */
        Type getType() const;
        
        /**
         * Returns the raw representation of the address
         *
         * @return the raw address in network byte order
         */
        u_int32_t getRawAddress() const;
        
        /**
         * Returns a string representation of the given IP address
         * @deprecated use operator<<() instead
         * @param addr raw address in network byte order
         * @param s the output stream to write the string to
         */
        static void toString(const u_int32_t addr, std::ostream *s); // IPv4
        
        /** length of a raw IPv4 address */
        static const u_int IPV4_RAW_LENGTH = 4;
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()
        
        friend std::ostream& operator<< (std::ostream&, const IPAddress&);
        friend class FlowID;
        
    private:

        /** type of the address */
        const Type        _type;
        
        /** raw address in network byte order */
        const u_int32_t   _addr;
        
        /** flags that string representation should truncate lower half */
        bool              _trunc;
        
        /** hash value (FNV-1a) */
        mutable std::size_t hash;

        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(IPAddress)

namespace std {
    // TODO add "extern" with C++0x
    /*extern*/ template<> bool equal_to<const IPAddress::Ptr>::operator() (const IPAddress::Ptr &, const IPAddress::Ptr &) const;
}

namespace std { namespace tr1 {
    // TODO add "extern" with C++0x
    /*extern*/ template<> std::size_t hash<const IPAddress::Ptr>::operator() (const IPAddress::Ptr) const;
}}

inline bool
IPAddress::equals(const IPAddress::Ptr & addr) const
{
    if (addr && _type == addr->getType() && _addr == addr->getRawAddress())
        return true;
    
    return false;
}

inline std::size_t
IPAddress::hashValue() const
{
    switch (this->_type)
    {
        case (IPv4) :
        {
            if (!hash)
            {
                hash = 2166136261UL;
                for (std::size_t i = 0; i < 4; ++i)
                {
                    hash ^= ((u_int8_t *) &_addr)[i];
                    hash *= 16777619UL;
                }
            }
            return hash;
            break;
        }
        case (IPv6) :
        {
            assert (false);
        }
    }

    assert (false);
    return 0;
}

inline
IPAddress::IPAddress(u_int32_t addr, bool trunc)
    : _type(IPv4),
      _addr(addr),
      _trunc(trunc),
      hash(0)
{
}

inline
IPAddress::~IPAddress()
{
}

inline void
IPAddress::toString(const u_int32_t addr, std::ostream *s)
{
    assert(s != 0);
    
    *s << (u_int)((u_int8_t *)&addr)[0]  << "."
       << (u_int)((u_int8_t *)&addr)[1]  << "."
       << (u_int)((u_int8_t *)&addr)[2]  << "."
       << (u_int)((u_int8_t *)&addr)[3];
}

inline IPAddress::Type
IPAddress::getType() const
{
    return _type;
}

inline u_int32_t
IPAddress::getRawAddress() const
{
    return _addr;
}

std::ostream& operator<< (std::ostream&, const IPAddress&);
std::ostream& operator<< (std::ostream&, const IPAddress::Ptr&);

#endif //__IP_ADDRESS_H__
