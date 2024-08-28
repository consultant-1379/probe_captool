/*
 * IPFragmentsID.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IP_FRAGMENTS_ID_H__
#define __IP_FRAGMENTS_ID_H__

#include <string>
#include <sstream>
#include <functional> // equal_to
#include <tr1/functional> // hash
#include <sys/types.h>

#include "util/poolable.h"

/**
 * Represents the identifier of fragmented IP packets
 *
 * @note see RFC815
 */
class IPFragmentsID
{
    public:

        /**
         * Constructor of IPFragmentsID
         *
         * @param source source IP address
         * @param destination destination IP address
         * @param identifier packet's IP identifier
         * @param protocol protocol type
         */
        IPFragmentsID(u_int32_t source, u_int32_t destination, u_int16_t identifier, u_int8_t protocol);

        /**
         * Destructor.
         */    
        ~IPFragmentsID();

        CAPTOOL_POOLABLE_DECLARE_METHODS()
    
    private:
        
        /** source IP address */
        u_int32_t     _srcIP;
        /** destination IP address */
        
        u_int32_t     _dstIP;
        
        /** IP identifier */
        u_int16_t     _id;
        
        /** protocol type */
        u_int8_t      _proto;

        friend class IPFragments;
        friend class std::equal_to<IPFragmentsID *>;
        friend class std::tr1::hash<IPFragmentsID *>;
        
        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(IPFragmentsID)

namespace std {
    template<> bool equal_to<IPFragmentsID *>::operator() (IPFragmentsID * const&,  IPFragmentsID * const&) const;
}

namespace std { namespace tr1 {
    template<> std::size_t hash<IPFragmentsID *>::operator() (IPFragmentsID *) const;
}}

inline
IPFragmentsID::IPFragmentsID(u_int32_t source, u_int32_t destination, u_int16_t identifier, u_int8_t protocol)
    : _srcIP(source),
      _dstIP(destination),
      _id(identifier),
      _proto(protocol)
{
    assert(_srcIP != 0);
    assert(_dstIP != 0);
    assert(_proto != 0);
}
        
inline
IPFragmentsID::~IPFragmentsID()
{
}

#endif // __IP_FRAGMENTS_ID_H__
