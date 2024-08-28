/*
 * IP.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IP_H__
#define __IP_H__

#include <cassert>
#include <sys/types.h>
#include <netinet/ip.h>
#include <string>
#include <ostream>
#include <tr1/unordered_map>
#include <libconfig.h++>

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"
#include "util/ObjectPool.h"
#include "ip/IPAddress.h"
#include "IPFragments.h"
#include "IPFragmentsID.h"

/**
 * Module for processing IPv4 and IPv6 packets.
 * @par %Module configuration
 * @code
 *        ip:
 *        {
 *            type = "IP";
 *
 *            connections = (                  // based on ip protocol field
 *                            (17, "udp")      // udp = 17, tcp = 6
 *            );
 *
 *            idFlows = false;                 // update IP address fields of flowID in packet? (not the case for the outer IP header)
 *            defrag = true;                   // enable / disable defragmentation (default = true)
 *            filterFragments = false;         // drop non-first fragments when _not_ defragmenting (default = false)
 *            ipv6Module = "ipv6_dump";        // IPv6 not yet supported, but this parameter can be used to forward IPv6 traffic to another module (e.g. PcapOutput)
 *        };
 * @endcode
 * Also honors the following security setting:
 * @code
 *        securityManager:
 *        {
 *            anonymize = true;                // show only upper half of IP addresses on output (Class-B network number)
 *        };
 * @endcode
 */
class IP : public captool::Module
{
    public:

        /**
         * Returns the source IP address of this module's protocol in the given packet
         *
         * @param captoolPacket the packet
         * @param truncate show only first half of the address in output
         * @return the source IP address of this protocol in the packet
         */
        IPAddress::Ptr getSourceIPAddressFrom(captool::CaptoolPacket* captoolPacket, bool truncate = false);

        /**
         * Returns the destination IP address of this module's protocol in the given packet
         *
         * @param captoolPacket the packet
         * @param truncate show only first half of the address in output
         * @return the destination IP address of this protocol in the packet
         */
        IPAddress::Ptr getDestinationIPAddressFrom(captool::CaptoolPacket* captoolPacket, bool truncate = false);
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit IP(std::string name);

        /**
         * Destructor.
         */    
        ~IP();

        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);

        // inherited from Module
        void getStatus(std::ostream *s, u_long runtime, u_int period);

        // inherited from Module
        void fixHeader(captool::CaptoolPacket* captoolPacket);

        // inherited from Module
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);

        // inherited from Module
        int getDatalinkType();

    protected:

        void initialize(libconfig::Config* config);
        virtual void configure (const libconfig::Setting &);
        
    private:

        /**
         * Processes an IPv4 packet for the main process method.
         *
         * @param captoolPacket the CaptoolPacket to be processed
         *
         * @return the connection module to be used
         */
        Module* processIPv4(captool::CaptoolPacket * captoolPacket);
        
        /**
         * Calculates checksum for the given IP header
         *
         * @param ip pointer to the IP header
         * @param len length of the header
         *
         * @return the generated checksum for the header
         */
        u_int16_t checksum(u_int16_t *ip, u_int len);

        /**
         * Cleans up timed out IP Fragments.
         *
         * @param time the current time
         */
        void fragmentsCleanup(const struct timeval *time);        
        
        /** true if the module should flowid the packet */
        bool                                  _idFlows;
        
        /** true if the module should defragment fragmented IP packets */
        bool                                  _defrag;
        
        /** true if the module should not keep non-first fragments if defragmentation is off */
        bool                                  _filterFragments;
        
        /** flag to truncate IP addresses on output */
        // FIXME currently only source address is ever truncated
        bool                                  _trunc;

        /** pair type for IPFramgnetID and IPFragment pairs */
        typedef std::pair<IPFragmentsID *, IPFragments *> FragmentsMapPair;
        
        /** map type for mapping an IPFragmentID to its IPFragments */
        typedef std::tr1::unordered_map <IPFragmentsID *, IPFragments *> FragmentsMap;
        
        /** map mapping an IPFragmentID to its IPFragment */
        FragmentsMap                          _fragments;
        
        /** object pool for IPFragments s */
        ObjectPool<IPFragments>               _fragmentsPool;
        
        /** the next packet's number when fragments cleanup is due */
        u_long                                _nextCleanupAt;
        
        /** maximum number of fragmented IP packets to keep in memory
         * (NB: _not_ fragments but to-be-assembled IP packets)
         */
        u_int                                 maxfragmented;
        
        /**
         * Structure for binding connections to protocols
         */
        struct Connection {
            /** transport protocol number */
            u_int8_t  protocol;
            /** output module */
            Module    *module;
        };
        
        /** array of connection structures */
        struct Connection *_connections;
        
        /** length of the connections array */
        u_int              _connectionsLength;
        
        /** the module which will handle (currently simply write to pcap file) IPv6 traffic */
        Module * _ipv6Module;
        
        /** period of fragment cleanups in term of packet numbers */
        static const u_int FRAGMENT_CLEANUP_INTERVAL = 10000;
        
        /** timeout value for fragments in seconds */
        static const int FRAGMENT_TIMEOUT = 1;

        /** Counters for per period and per transport protocol (e.g. UDP, TCP, ESP) traffic statistics */
        u_int64_t _trafficStatistics[256];

        /** Total traffic for the current period */
        u_int64_t _totalTraffic;
};

inline
IPAddress::Ptr
IP::getSourceIPAddressFrom(captool::CaptoolPacket* captoolPacket, bool trunc)
{
    assert(captoolPacket != 0);
    
    struct iphdr* ip = (struct iphdr *)captoolPacket->getSegment(this, 0);
    if (ip == 0)
    {
        return IPAddress::Ptr();
    }
    // assume IPv4
    return IPAddress::Ptr(new IPAddress(ip->saddr, trunc));
}

inline
IPAddress::Ptr
IP::getDestinationIPAddressFrom(captool::CaptoolPacket* captoolPacket, bool trunc)
{
    assert(captoolPacket != 0);
    
    struct iphdr* ip = (struct iphdr *)captoolPacket->getSegment(this, 0);
    if (ip == 0)
    {
        return IPAddress::Ptr();
    }
    // assume IPv4
    return IPAddress::Ptr(new IPAddress(ip->daddr, trunc));
}

#endif // __IP_H__
