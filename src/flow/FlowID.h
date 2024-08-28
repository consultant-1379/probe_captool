/*
 * FlowID.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_ID_H__
#define __FLOW_ID_H__

#include <cassert>

#include <string>

#include <stdio.h>
#include <ostream>
#include <sstream>
#include <boost/intrusive_ptr.hpp>
#include <netinet/ip.h>

#include "util/poolable.h"
#include <tr1/functional> // hash
#include "ip/IPAddress.h"
#include "util/RefCounter.h"

using std::string;

/**
 * Class representing a flow identifier.
 */
class FlowID : public RefCounter
{
    public:
        
        /** Convenience type for safe pointers to FlowID instances */
        typedef boost::intrusive_ptr<FlowID>    Ptr;
        
        /**
         * Constructor.
         */
        FlowID();
        
        /**
         * Copy constructor.
         *
         * @param fid the FlowID to copy
         */
        explicit FlowID(const FlowID & fid);
        
        /**
         * Resets the flow to its initial state.
         */
        void reset();
        
        /**
         * Swaps source/destination IP-s and ports.
         */
        void swap();
        
        /**
         * Sets the IP addresses and protocol of the FlowID.
         *
         * @param srcIP source IP address
         * @param dstIP destination IP address
         * @param protocol protocol type
         */
        void setIP(const IPAddress::Ptr & srcIP, const IPAddress::Ptr & dstIP, u_int8_t protocol);
        
        /**
         * Sets the transport ports of the FlowID.
         *
         * @param srcPort source port
         * @param dstPort destination port
         */
        void setTransport(u_int16_t srcPort, u_int16_t dstPort);
        
        /**
         * Returns the source IP address.
         *
         * @return source IP
         */
        const IPAddress::Ptr & getSourceIP() const;
        
        /**
         * Returns the destination IP address.
         *
         * @return destination IP
         */
        const IPAddress::Ptr & getDestinationIP() const;
        
        /**
         * Returns the source port.
         *
         * @return source port
         */
        u_int16_t getSourcePort() const;
        
        /**
         * Returns the destination port.
         *
         * @return destination port
         */
        u_int16_t getDestinationPort() const;
        
        /**
         * Returns the protocol type.
         *
         * @return protocol type
         */
        u_int8_t  getProtocol() const;
        
        /**
         * Returns true if the given IP-port pair is the source of this flow.
         *
         * @param ip ip address
         * @param port port in network byte order
         *
         * @return true if the IP-port pair is the source
         */
        bool isSource(const IPAddress::Ptr & ip, u_int16_t port) const;
        
        /**
         * Returns true if the given IP-port pair is the destination of this flow.
         *
         * @param ip ip address
         * @param port port in network byte order
         *
         * @return true if the IP-port pair is the destination
         */
        bool isDestination(const IPAddress::Ptr & ip, u_int16_t port) const;
        
        /**
         * Returns true if all IP and transport fields are set
         */
        bool isSet() const;
        
        /**
         * Returns a string representation of a particular transport protocol
         *
         * @param protocol the IP protocol value (as u_int8_t) to be converted to its string representation
         */
        static string ipProtocolToString(u_int8_t protocol);
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()
       
        friend std::ostream& operator<<(std::ostream&, const FlowID&);
        
    private:
        
        /** true if the ip address and protocol is set */
        bool   _addressSet;
        
        /** true if the transport ports are set */
        bool   _transportSet;
        
        /** ip address of source */
        IPAddress::Ptr _srcIP;
        
        /** port of source in network byte order*/
        u_int16_t _srcPort;
        
        /** ip address of destination */
        IPAddress::Ptr _dstIP;
        
        /** port of destination in network byte order*/
        u_int16_t _dstPort;
        
        /** protocol type */
        u_int8_t  _protocol;
        
        friend class FlowIDEquals;
        friend class FlowIDEqualsStrict;
        friend class FlowIDHasher;

        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(FlowID)

namespace std { namespace tr1 {
    // TODO add "extern" with C++0x
    /*extern*/ template<> std::size_t hash<const FlowID::Ptr>::operator() (const FlowID::Ptr) const;
}}

inline
FlowID::FlowID()
    : _addressSet(false),
      _transportSet(false),
      _srcIP(),
      _srcPort(0),
      _dstIP(),
      _dstPort(0),
      _protocol(0)
{
}

inline
FlowID::FlowID(const FlowID & fid)
    : _addressSet(fid._addressSet),
      _transportSet(fid._transportSet),
      _srcIP(),
      _srcPort(fid._srcPort),
      _dstIP(),
      _dstPort(fid._dstPort),
      _protocol(fid._protocol)
{
        if (fid._srcIP != 0)
        {
            _srcIP = fid._srcIP;
        }
        if (fid._dstIP != 0)
        {
            _dstIP = fid._dstIP;
        }
}

inline
void
FlowID::swap()
{
    bool srctrunc = _srcIP ? _srcIP->_trunc : false;
    bool dsttrunc = _dstIP ? _dstIP->_trunc : false;
    _srcIP.swap(_dstIP);
    if (_srcIP)
        _srcIP->_trunc = srctrunc;
    if (_dstIP)
        _dstIP->_trunc = dsttrunc;
    u_int16_t tmp = _srcPort;
    _srcPort = _dstPort;
    _dstPort = tmp;
}

inline void
FlowID::reset()
{
    _addressSet = false;
    _transportSet = false;
    
    _srcIP.reset();
    _dstIP.reset();
    _srcPort = 0;
    _dstPort = 0;
    _protocol = 0;
}

inline void
FlowID::setIP(const IPAddress::Ptr & srcIP, const IPAddress::Ptr & dstIP, u_int8_t protocol)
{
    assert(protocol != 0);
    
    _srcIP = srcIP;
    _dstIP = dstIP;
    _protocol = protocol;
    
    if (_srcIP && _dstIP)
        _addressSet = true;

    // No need to set ports for transport layers other than TCP and UDP
    if (_protocol != IPPROTO_TCP && _protocol != IPPROTO_UDP)
        _transportSet = true;
}

inline void
FlowID::setTransport( u_int16_t srcPort, u_int16_t dstPort)
{
    _srcPort = srcPort;
    _dstPort = dstPort;
    
    _transportSet = true;
}

inline bool
FlowID::isSource(const IPAddress::Ptr & ip, u_int16_t port) const
{
    return _addressSet && _transportSet && _srcIP->equals(ip) && _srcPort == port;
}

inline bool
FlowID::isDestination(const IPAddress::Ptr & ip, u_int16_t port) const
{
    return _addressSet && _transportSet && _dstIP->equals(ip) && _dstPort == port;
}

inline bool
FlowID::isSet() const
{
    return (_addressSet && _transportSet);
}

inline const IPAddress::Ptr &
FlowID::getSourceIP() const
{
    return _srcIP;
}

inline const IPAddress::Ptr &
FlowID::getDestinationIP() const
{
    return _dstIP;
}

inline u_int16_t
FlowID::getSourcePort() const
{
    return _srcPort;
}

inline u_int16_t
FlowID::getDestinationPort() const
{
    return _dstPort;
}

inline u_int8_t
FlowID::getProtocol() const
{
    return _protocol;
}

#endif // __FLOW_ID_H__
