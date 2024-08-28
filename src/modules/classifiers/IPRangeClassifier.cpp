/*
 * IPRangeClassifier.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "IPRangeClassifier.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <iostream>
#include <sstream>

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(IPRangeClassifier)

IPRangeClassifier::IPRangeClassifier(string name)
    : Module(name)
{
}

IPRangeClassifier::~IPRangeClassifier()
{
}

void
IPRangeClassifier::initialize(libconfig::Config* config)
{
    assert(config != 0);

    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);

    // Register all IP range signatures
    registerSignatures("ip-range");
}

Module*
IPRangeClassifier::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);

    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    Flow * flow = captoolPacket->getFlow().get();
    if (!flow)
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }

    // Source and destination IPs (in host byte order)
    u_int32_t srcIP = ntohl(flow->getID()->getSourceIP()->getRawAddress());
    u_int32_t dstIP = ntohl(flow->getID()->getDestinationIP()->getRawAddress());

    // Go through each IP range and check whether it matches the source or destination IP
    for (multimap<Hintable::Hint,IPRange>::const_iterator it = _ipRangeMap.begin(); it != _ipRangeMap.end(); ++it)
    {
        Hintable::Hint hint = it->first;
        u_int32_t address = it->second.address;
        u_int32_t netmask = it->second.netmask;
        if ((srcIP & netmask) == address || (dstIP & netmask) == address)
        {
            flow->setHint(hint.first, hint.second);
        }
    }

    return _outDefault;
}

void
IPRangeClassifier::registerSignature(unsigned blockId, const Signature * signature)
{
    Hintable::Hint hint = std::make_pair(blockId, signature->getId());

    // Parse all IP range blocks
    const Node::NodeList ipRanges = signature->getXmlDefinition()->get_children("ip");
    for (Node::NodeList::const_iterator it = ipRanges.begin(); it != ipRanges.end(); ++it)
    {
        const Element* ipRange = dynamic_cast<const Element*>(*it);

        IPRange range;

        // Parse IP address
        string addressString = ipRange->get_attribute_value("address");
        struct in_addr address;
        int result = inet_pton(AF_INET, addressString.c_str(), &address);
        if (result < 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("Invalid IP address " << addressString << " in signature " << signature->getId() << " of block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId))
            exit(-1);
        }
        range.address = ntohl(address.s_addr);

        // Parse netmask
        string netmaskString = ipRange->get_attribute_value("netmask");
        // when netmask is not specified, the entry is considered as one single address not as a subnet
        unsigned netmaskLength = 32;
        if (netmaskString != "")
        {
            std::istringstream(netmaskString) >> netmaskLength;
            if (netmaskLength < 1 || netmaskLength > 32)
            {
                CAPTOOL_MODULE_LOG_SEVERE("Invalid netmask length " << netmaskString << " in signature " << signature->getId() << " of block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId))
                exit(-1);
            }
        }
        range.netmask = 0xffffffff << (32 - netmaskLength);

        // Make sure that subnet address is correct
        if (range.address != (range.address & range.netmask))
        {
            CAPTOOL_MODULE_LOG_SEVERE("Invalid subnet specification " << addressString << "/" << netmaskLength << " in signature " << signature->getId() << " of block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId))
            exit(-1);
        }

        // Register IP range
        _ipRangeMap.insert(std::make_pair(hint,range));
    }
}
