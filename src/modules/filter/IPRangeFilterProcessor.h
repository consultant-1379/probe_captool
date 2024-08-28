/*
 * IPRangeFilterProcessor.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IP_RANGE_FILTER_PROCESSOR_H__
#define __IP_RANGE_FILTER_PROCESSOR_H__

#include <set>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "captoolpacket/CaptoolPacket.h"
#include "FilterProcessor.h"

using std::set;
using captool::CaptoolPacket;

class IPRangeFilterProcessor : public FilterProcessor
{
    public:

        /** Identifies whether filtering is applied to subscriber side or peer/server side ports */
        enum EndpointType
        {
            SUBSCRIBER,
            PEER
        };

        typedef struct
        {
            u_int32_t   address; // in host byte order
            u_int32_t   netmask; // in host byte order
        } IPRange;

        /**
         * Creates a new IPRangeFilterProcessor
         *
         * @param endpointType identifies whether filtering is applied to subscriber or peer/server ports
         * @param values the set of strings for which the filter will return "pass"
         */
        IPRangeFilterProcessor(EndpointType endpointType, set<string> values);

        /**
         * Returns whether a packet of the given flow passes the filter or no
         */
        bool test(const CaptoolPacket *, const Flow *);

    private:

        /** identifies whether filtering is applied to subscriber or peer/server ports */
        EndpointType    _endpointType;

        /** the set of strings for which the filter returns "pass" */
        set<IPRange*>        _values;

        void registerIpRange(const string& ipRange);
};

inline
IPRangeFilterProcessor::IPRangeFilterProcessor(EndpointType endpointType, set<string> values) :
    FilterProcessor(),
    _endpointType(endpointType)
{
    for (set<string>::const_iterator it = values.begin(); it != values.end(); ++it)
    {
        registerIpRange(*it);
    }
}

inline void
IPRangeFilterProcessor::registerIpRange(const string& ipRange)
{
    // Split IP address and netmask substrings
    size_t separator = ipRange.find_first_of('/');
    string ipString = ipRange.substr(0, separator);
    string netmaskString = (separator == string::npos) ? "32" : ipRange.substr(separator+1, ipRange.length() - separator - 1);

    // Parse IP address
    struct in_addr address;
    int result = inet_pton(AF_INET, ipString.c_str(), &address);
    if (result < 0)
    {
        CAPTOOL_LOG_WARNING("Invalid IP address " << ipString << " among filter values, skipping it")
        return;
    }

    // Parse netmask
    int netmaskLength;
    std::istringstream(netmaskString) >> netmaskLength;
    if (netmaskLength < 1 || netmaskLength > 32)
    {
        CAPTOOL_LOG_WARNING("Invalid netmask length " << netmaskString << " among filter values, skipping it")
        return;
    }
    
    IPRange * range = new IPRange();
    range->address = ntohl(address.s_addr);
    range->netmask = 0xffffffff << (32 - netmaskLength);

    // Make sure that subnet address is correct
    if (range->address != (range->address & range->netmask))
    {
        CAPTOOL_LOG_WARNING("Invalid subnet specification " << ipRange << " among filter values, skipping it")
        delete range;
        return;
    }
    
    _values.insert(range);
}

inline bool
IPRangeFilterProcessor::test(const CaptoolPacket *, const Flow * flow)
{
    // TBD: this will not work when using FlowOutput instead of FlowOutputStrict!
    u_int32_t address = _endpointType == SUBSCRIBER ?
            flow->getID()->getSourceIP()->getRawAddress() :
                flow->getID()->getDestinationIP()->getRawAddress();

    for (set<IPRange*>::const_iterator it = _values.begin(); it != _values.end(); ++it)
    {
        IPRange * subnet = *it;
        if (subnet->address == (ntohl(address) & subnet->netmask))
        {
            return true;
        }
    }

    return false;
}

#endif /* __IP_RANGE_FILTER_PROCESSOR_H__ */
