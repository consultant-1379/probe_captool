/*
 * TCP.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "modulemanager/ModuleManager.h"

#include "TCP.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(TCP)

TCP::TCP(string name)
    : Module(name),
      _idFlows(false),
      _connections(0),
      _connectionsLength(0)
{
}

TCP::~TCP()
{
    delete[] (_connections);
}

void
TCP::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    /* configure connections */

    libconfig::Setting& connectionSettings = config->lookup("captool.modules." + _name + ".connections");
    
    _connectionsLength = 0;
    _connections = new struct Connection[connectionSettings.getLength()];
    
    for (int i=0; i<connectionSettings.getLength(); ++i)
    {
        libconfig::Setting& connection = connectionSettings[i];
        
        if (connection.getType() != libconfig::Setting::TypeList)
        {
            CAPTOOL_MODULE_LOG_SEVERE(i << "th connection setting is not a list")
            exit(-1);
        }

        if (connection.getLength() != 2)
        {
            CAPTOOL_MODULE_LOG_SEVERE("list no. " << i << " does not have a length of 2")
            exit(-1);
        }

        // skip default
        if (connection[0].getType() == libconfig::Setting::TypeString && Module::DEFAULT_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            continue;
        }
        
        // check list
        if (connection[0].getType() != libconfig::Setting::TypeInt)
        {
            CAPTOOL_MODULE_LOG_SEVERE("firt element in list no. " << i << " is not a number.")
            exit(-1);
        }
        
        if (connection[1].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("second element in list no. " << i << " is not a string.")
            exit(-1);
        }
        
        int port = connection[0];
        
        if (port < 0 || port > 65535)
        {
            CAPTOOL_MODULE_LOG_SEVERE("port number must be between 0 and 65535.")
            exit(-1);
        }
        
        string moduleName = connection[1];
        Module *module = ModuleManager::getInstance()->getModule(moduleName);
        if (module == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
            exit(-1);
        }

        _connections[_connectionsLength].port = htons(port);
        _connections[_connectionsLength].module = module;
        ++_connectionsLength;
        
    }
    
    if (config->exists("captool.modules." + _name))
        configure(config->lookup("captool.modules." + _name));
}

void
TCP::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("idFlows", _idFlows))
        CAPTOOL_MODULE_LOG_CONFIG((_idFlows ? "" : "not ") << "filling in flow ID elements.")
}

Module*
TCP::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    // get payload
    size_t payloadLength = 0;
    struct tcphdr* tcp = (struct tcphdr*)captoolPacket->getPayload(&payloadLength);

    assert(tcp != 0);

    u_int headerLength = tcp->doff * 4;
    
    if (payloadLength < headerLength)
    {
        CAPTOOL_MODULE_LOG_INFO("payload is too short for a TCP header. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }

    // save total tcp length;
    captoolPacket->saveSegment(this, headerLength);

    // ID flow
    if (_idFlows)
    {
        captoolPacket->getFlowID().setTransport(tcp->source, tcp->dest);
    }

    // forward
    for (u_int i=0; i<_connectionsLength; ++i)
    {
        if (_connections[i].port == tcp->source || _connections[i].port == tcp->dest)
        {
            return _connections[i].module;
        }
    }
    
    return _outDefault;
}

void
TCP::describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s)
{
    assert(captoolPacket != 0);
    assert(s != 0);

    CAPTOOL_MODULE_LOG_FINEST("describing packet.")
    
    struct tcphdr* tcp = (struct tcphdr*)captoolPacket->getSegment(this, 0);
 
    assert(tcp != 0);
    
    *s << "src: " << ntohs(tcp->source)
      << ", dst: " << ntohs(tcp->dest);

    if (tcp->syn) { *s << " SYN"; }
    if (tcp->fin) { *s << " FIN"; }
    if (tcp->ack) { *s << " ACK"; }
}
