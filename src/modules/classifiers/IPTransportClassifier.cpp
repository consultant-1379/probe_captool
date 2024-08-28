/*
 * IPTransportClassifier.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <string>
#include <cctype>
#include <cstdlib>

#include "modulemanager/ModuleManager.h"
#include "flow/Flow.h"
#include "IPTransportClassifier.h"

using std::string;
using std::pair;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(IPTransportClassifier)

IPTransportClassifier::IPTransportClassifier(string name)
    : Module(name)
{
}

IPTransportClassifier::~IPTransportClassifier()
{
}

void
IPTransportClassifier::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    // Register all ip-protocol signatures
    registerSignatures("ip-protocol");
}

void
IPTransportClassifier::registerSignature(unsigned blockId, const Signature * signature)
{
    unsigned protocol;
 
    getattrval(signature->getXmlDefinition(), "value") >> protocol;
    if (protocol > 255)
    {
        CAPTOOL_MODULE_LOG_SEVERE("IP protocol value of ip-transport signature is out of the range 0-255 within block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId) << ": " << protocol)
        exit(-1);
    }
    HintMap::const_iterator it = _hintMap.find(protocol);
    if (it != _hintMap.end())
    {
        CAPTOOL_MODULE_LOG_SEVERE("IP protocol value " << protocol << " used in more than one signature")
        exit(-1);
    }
    
    CAPTOOL_MODULE_LOG_INFO("Block: " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId) << ", sigId: " << signature->getId() << " ip protocol value: " << protocol)
    
    _hintMap[(u_int8_t)protocol] = std::make_pair(blockId, signature->getId());
}

Module*
IPTransportClassifier::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    // Get associated flow
    Flow * flow = captoolPacket->getFlow().get();
    if (!flow)
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }

    // Find classification hint corresponding to the given IP transport protocol
    u_int8_t protocol = flow->getID()->getProtocol();
    HintMap::const_iterator it = _hintMap.find(protocol);
    if (it != _hintMap.end())
    {
        Hintable::Hint hint = it->second;
        flow->setHint(hint.first, hint.second);
    }

    return _outDefault;
}

