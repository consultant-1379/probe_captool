/*
 * PortClassifier.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>

#include <netinet/in.h>

#include "modulemanager/ModuleManager.h"

#include "PortClassifier.h"
#include "flow/Flow.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(PortClassifier)

PortClassifier::PortClassifier(string name)
    : Module(name)
{
}

PortClassifier::~PortClassifier()
{
}

void
PortClassifier::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    // Register all port signatures
    registerSignatures("port");
}

Module*
PortClassifier::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")
    
    Flow * flow = captoolPacket->getFlow().get();
    if (!flow)
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }
    
    u_int8_t transportType = flow->getID()->getProtocol();
    u_int16_t srcPort = flow->getID()->getSourcePort();
    u_int16_t dstPort = flow->getID()->getDestinationPort();

    if (transportType == IPPROTO_UDP)
    {
        PortMap::const_iterator it = udpPorts.find(srcPort);
        if (it != udpPorts.end())
        {
            flow->setHint(it->second.first, it->second.second);
        }
        it = udpPorts.find(dstPort);
        if (it != udpPorts.end())
        {
            flow->setHint(it->second.first, it->second.second);
        }
    }
    else if (transportType == IPPROTO_TCP)
    {
        PortMap::const_iterator it = tcpPorts.find(srcPort);
        if (it != tcpPorts.end())
        {
            flow->setHint(it->second.first, it->second.second);
        }
        it = tcpPorts.find(dstPort);
        if (it != tcpPorts.end())
        {
            flow->setHint(it->second.first, it->second.second);
        }
    }
        
    return _outDefault;
}

void
PortClassifier::registerSignature(unsigned blockId, const Signature * signature)
{
    if (signature->isFinal())
    {
        CAPTOOL_MODULE_LOG_SEVERE("Port-based signature should not be tagged final (" << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId) << "," << signature->getId() << ")")
        exit(-1);
    }

    u_int16_t port;
    string type;
 
    getattrval(signature->getXmlDefinition(), "value") >> port;
    type = signature->getXmlDefinition()->get_attribute_value("type");
    
    CAPTOOL_MODULE_LOG_INFO("Block: " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId) << ", sigId: " << signature->getId() << ", " << type << " port: " << port)
    
    if (type == "tcp" || type == "any")
    {
        if (tcpPorts.find(htons(port)) != tcpPorts.end())
        {
            CAPTOOL_MODULE_LOG_SEVERE("TCP port " << port << " is used in more than one signature")
            exit(-1);
        }
        tcpPorts[htons(port)] = std::make_pair(blockId, signature->getId());
    }
    if (type == "udp" || type == "any")
    {
        if (udpPorts.find(htons(port)) != udpPorts.end())
        {
            CAPTOOL_MODULE_LOG_SEVERE("UDP port " << port << " is used in more than one signature")
            exit(-1);
        }
        udpPorts[htons(port)] = std::make_pair(blockId, signature->getId());
    }
}
