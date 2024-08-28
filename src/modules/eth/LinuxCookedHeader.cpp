/*
 * LinuxCookedHeader.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <pcap-bpf.h>
//#include <netinet/ether.h>

#include "sll.h"

#include "modulemanager/ModuleManager.h"

#include "LinuxCookedHeader.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(LinuxCookedHeader)

const u_int16_t LinuxCookedHeader::VLAN_TYPE = 0x0081; // htons(0x8100)

LinuxCookedHeader::LinuxCookedHeader(string name)
    : Module(name),
      _connections(0),
      _connectionsLength(0)
{
}

LinuxCookedHeader::~LinuxCookedHeader()
{
    delete[] (_connections);
}

void
LinuxCookedHeader::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    /* configure connections */

    libconfig::Setting& connectionSettings = config->lookup("captool.modules." + _name + ".connections");
    
    _connectionsLength = 0;
    _connections = new struct Connection[connectionSettings.getLength()];
    
    for (int i=0; i<connectionSettings.getLength(); ++i) {
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
        
        int protocol = connection[0];
        
        if (protocol < 0 || protocol > 65535)
        {
            CAPTOOL_MODULE_LOG_SEVERE("protocol number must be between 0 and 65535.")
            exit(-1);
        }
        
        string moduleName = connection[1];
        Module *module = ModuleManager::getInstance()->getModule(moduleName);
        if (module == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
            exit(-1);
        }

        _connections[_connectionsLength].protocol = htons(protocol);
        _connections[_connectionsLength].module = module;
        ++_connectionsLength;
        
    }
}

Module*
LinuxCookedHeader::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    // request payload from packet
    size_t payloadLength = 0;
    struct sll_header* sll = (struct sll_header*)captoolPacket->getPayload(&payloadLength);

    assert(sll != 0);
    
    u_int headerLength = SLL_HDR_LEN;
    
    // skip VLAN tags
    u_int16_t *typeField = &(sll->sll_protocol);
    while (*typeField == VLAN_TYPE)
    {
        CAPTOOL_MODULE_LOG_FINE("stripped VLAN tag (no. " << captoolPacket->getPacketNumber() << ")")
        headerLength += 4;
        typeField += 2;
    }

    if (payloadLength < headerLength)
    {
        CAPTOOL_MODULE_LOG_INFO("payload is too short for a LinuxCookedHeader header. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }
    
    // save length of header on protocol stack
    captoolPacket->saveSegment(this, headerLength);

    
    // forward
    for (u_int i=0; i<_connectionsLength; ++i)
    {
        if (_connections[i].protocol == *typeField)
        {
            return _connections[i].module;
        }
    }
    
    return _outDefault;
}

void
LinuxCookedHeader::describe(const CaptoolPacket *captoolPacket, std::ostream *s)
{
    assert(captoolPacket != 0);
    assert(s != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("describing packet.")
    
    *s << "linux cooked header.";
}

int
LinuxCookedHeader::getDatalinkType() {
    return DLT_LINUX_SLL;
}

