/*
 * DPI.cpp -- part of Captool, a traffic profiling framework
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
#include <pcre.h>
#include <cstdlib>

#include "modulemanager/ModuleManager.h"
#include "flow/Flow.h"
#include "DPI.h"

using std::string;
using std::pair;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(DPI)

DPI::DPI(string name)
    : Module(name)
{
}

DPI::~DPI()
{
//    This results in double free problem for signatures with tyep="any"
//    for (SignatureMap::const_iterator i = signatureMapTCP.begin(); i != signatureMapTCP.end(); ++ i)
//        free(i->second);
//    for (SignatureMap::const_iterator i = signatureMapUDP.begin(); i != signatureMapUDP.end(); ++ i)
//        free(i->second);
}

void
DPI::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    // Register all DPI signatures
    registerSignatures("dpi");
}

void
DPI::registerSignature(unsigned blockId, const Signature * signature)
{
    string regexp = signature->getXmlDefinition()->get_attribute_value("regexp");
    string type = signature->getXmlDefinition()->get_attribute_value("type");
    
    // If type is invalid, XML validation will fail, so no need to check here
    CAPTOOL_MODULE_LOG_INFO("Block: " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId) << ", sigId: " << signature->getId() << ", regexp: " << regexp << ", type: " << type)
    
    // Compile regexp
    const char *error;
    int erroroffset;
    
    pcre * compiledRegexp = pcre_compile(regexp.c_str(), 0, &error, &erroroffset, NULL);
    if (compiledRegexp == NULL)
    {
        CAPTOOL_MODULE_LOG_WARNING("Could not compile regexp: " << regexp)
        CAPTOOL_MODULE_LOG_WARNING("Error at character " << erroroffset << ": " << error)
        CAPTOOL_MODULE_LOG_WARNING("See signature " << signature->getId() << " of block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId))
        exit(-1);
    }
    
    // Register hint + regexp in the signature map
    Hintable::Hint hint = std::make_pair(blockId, signature->getId());
    
    if (type == "any" || type == "tcp")
    {
        signatureMapTCP.insert(std::make_pair(hint, compiledRegexp));
    }
    if (type == "any" || type == "udp")
    {
        signatureMapUDP.insert(std::make_pair(hint, compiledRegexp));
    }
}

Module*
DPI::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    // get payload
    size_t payloadLength = 0;
    const char * payload = (char *)captoolPacket->getPayload(&payloadLength);
    
    if (payloadLength == 0)
    {
        return _outDefault;
    }

    // Get associated flow
    Flow * flow = captoolPacket->getFlow().get();
    if (!flow)
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }

    // Select UDP or TCP signature tables based on flow type and drop traffic which is not UDP or TCP
    u_int8_t protocol = flow->getID()->getProtocol();
    SignatureMap * signatureMap = protocol == IPPROTO_TCP ? &signatureMapTCP : (protocol == IPPROTO_UDP ? &signatureMapUDP : NULL);
    if (!signatureMap)
        return _outDefault;

    // Match signatures
    for (SignatureMap::const_iterator it = signatureMap->begin(); it != signatureMap->end(); ++it)
    {
        Hintable::Hint hint = it->first;
        pcre * regexp = it->second;
        
        int ovector[10];
        int rc;
    
        rc = pcre_exec(regexp, NULL, payload , payloadLength, 0, 0, ovector, 10);
        if (rc > 0)
        {
            flow->setHint(hint.first, hint.second);
        }
    }
    
    return _outDefault;
}

void
DPI::describe(const captool::CaptoolPacket *, std::ostream *)
{
}
