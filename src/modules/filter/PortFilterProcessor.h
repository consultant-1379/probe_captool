/*
 * PortFilterProcessor.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PORT_FILTER_H__
#define __PORT_FILTER_H__

#include <set>

#include "captoolpacket/CaptoolPacket.h"
#include "FilterProcessor.h"

using std::set;
using captool::CaptoolPacket;

class PortFilterProcessor : public FilterProcessor
{
    public:

        /** Identifies transport type */
        enum TransportType
        {
            ANY,
            TCP,
            UDP
        };

        /** Identifies whether filtering is applied to subscriber side or peer/server side ports */
        enum EndpointType
        {
            SUBSCRIBER,
            PEER
        };

        /**
         * Creates a new PortFilterProcessor
         *
         * @param transportType identifies transport protocol constraints
         * @param endpointType identifies whether filtering is applied to subscriber or peer/server ports
         * @param values the set of strings for which the filter will return "pass"
         */
        PortFilterProcessor(TransportType transportType, EndpointType endpointType, set<int> values);

        /**
         * Returns whether a packet of the given flow passes the filter or no
         */
        bool test(const CaptoolPacket *, const Flow *);

    private:

        /** Identifies transport protocol constraints */
        TransportType   _transportType;

        /** identifies whether filtering is applied to subscriber or peer/server ports */
        EndpointType    _endpointType;

        /** the set of strings for which the filter returns "pass" */
        set<int>        _values;
};

inline
PortFilterProcessor::PortFilterProcessor(TransportType transportType, EndpointType endpointType, set<int> values) :
    FilterProcessor(),
    _transportType(transportType),
    _endpointType(endpointType),
    _values(values)
{
}

inline bool
PortFilterProcessor::test(const CaptoolPacket *, const Flow * flow)
{
    u_int8_t flowTransportType = flow->getID()->getProtocol();
    if (_transportType == TCP && flowTransportType != 6) return false;
    if (_transportType == UDP && flowTransportType != 17) return false;

    // TBD: this will not work when using FlowOutput instead of FlowOutputStrict!
    u_int16_t port = _endpointType == SUBSCRIBER ? flow->getID()->getSourcePort() : flow->getID()->getDestinationPort();

    set<int>::const_iterator it = _values.find(port);
    return it != _values.end();
}

#endif /* __PORT_FILTER_H__ */
