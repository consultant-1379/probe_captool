/*
 * ETH.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>
#include <sstream>
#include <fstream>

#include <arpa/inet.h>
#include <netinet/ether.h>

#include "modulemanager/ModuleManager.h"
#include "ETH.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(ETH)

const u_int16_t ETH::VLAN_TYPE = 0x0081; // htons(0x8100)
        
ETH::ETH(string name)
    : Module(name),
      _connections(0),
      _connectionsLength(0),
      _useGatewayAddressList(false),
      setEquipmentID(false)
{
}

ETH::~ETH()
{
    delete[] (_connections);
}

void
ETH::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    const string mygroup = "captool.modules." + _name;
    
    /* configure connections */

    libconfig::Setting& connectionSettings = config->lookup(mygroup + ".connections");
    
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
    
    std::string _gatewayAddressListFile;
    
    // get the name of txt file with gateway ethernet addresses
    if (!config->lookupValue(mygroup + ".gatewayAddressFile", _gatewayAddressListFile))
    {
        CAPTOOL_MODULE_LOG_INFO("gatewayAddressFile not set (this is the default option for most configurations)")
    } else {
        CAPTOOL_MODULE_LOG_INFO("using gatewayAddressFile " << _gatewayAddressListFile << " to determine direction of traffic.")
        
        std::ifstream stream;
        std::string line;
        
        stream.open(_gatewayAddressListFile.c_str());
        if (!stream)
        {
            CAPTOOL_MODULE_LOG_WARNING("Could not open gateway address list file " << _gatewayAddressListFile)
            return;
        }
        
        while (stream >> line)
        {
            try 
            {
                MACAddress::Ptr gatewayAddress = MACAddress::Ptr(new MACAddress(line));
                _gatewayAddressMap.insert(std::pair<MACAddress::Ptr, bool>(gatewayAddress, true));
            } 
            catch (MACAddressException)
            {
                CAPTOOL_MODULE_LOG_WARNING(line << " is not a valid gateway MAC address;  skipping it.")
            }
        }
        
        stream.close();
        
        _useGatewayAddressList = true;
    }
    
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));
}

void
ETH::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("setEquipmentID", setEquipmentID))
    {
        if (setEquipmentID)
            CAPTOOL_MODULE_LOG_CONFIG("Will set MAC address as equipment ID.")
    }
}

Module*
ETH::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    // request payload from packet
    size_t payloadLength = 0;
    struct ether_header* eth = (struct ether_header*)captoolPacket->getPayload(&payloadLength);

    assert(eth != 0);
    
    u_int headerLength = ETHER_HDR_LEN;
    
    // skip VLAN tags
    u_int16_t *typeField = &(eth->ether_type);
    while (*typeField == VLAN_TYPE)
    {
        CAPTOOL_MODULE_LOG_FINE("stripped VLAN tag (no. " << captoolPacket->getPacketNumber() << ")")
        headerLength += 4;
        typeField += 2;
    }

    if (payloadLength < headerLength)
    {
        CAPTOOL_MODULE_LOG_INFO("payload is too short for a ETH header. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }

    if (MACAddress::isBroadcast((uint8_t*) (eth->ether_dhost))) {
        CAPTOOL_MODULE_LOG_INFO("Packet sent to broadcast Ethernet address. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;    
    }
    
    // save length of header on protocol stack
    captoolPacket->saveSegment(this, headerLength);

    // Determine direction of flows based on the mac address of gateway routers
    if (_useGatewayAddressList) 
    {
        bool gatewayToGatewayPacket = false;
        CaptoolPacket::Direction dir = CaptoolPacket::UNDEFINED_DIRECTION;
        
        MACAddress::Ptr srcMac = MACAddress::Ptr(new MACAddress((uint8_t*) &eth->ether_shost));
        
        MACAddressMap::const_iterator iter = _gatewayAddressMap.find(srcMac);
        if (iter != _gatewayAddressMap.end()) 
        {
            dir = CaptoolPacket::DOWNLINK;
        }
        
        MACAddress::Ptr dstMac = MACAddress::Ptr(new MACAddress(eth->ether_dhost));
        iter = _gatewayAddressMap.find(dstMac);
        if (iter != _gatewayAddressMap.end()) 
        {
            if (dir == CaptoolPacket::DOWNLINK) 
            {
                CAPTOOL_MODULE_LOG_INFO("Inter-gateway packet (not sent by a subscriber). Dropping packet (no. " << captoolPacket->getPacketNumber() << ")")
                gatewayToGatewayPacket = true;
            } 
            else
            {
                dir = CaptoolPacket::UPLINK;
            }
        }

        if (dir == CaptoolPacket::UNDEFINED_DIRECTION) 
        {
            CAPTOOL_MODULE_LOG_INFO("Local communication not going through the gateway. Dropping packet (no. " << captoolPacket->getPacketNumber() << ")")
        }
        
        if (dir == CaptoolPacket::UNDEFINED_DIRECTION || gatewayToGatewayPacket)
        {
            return 0;
        }

        captoolPacket->setDirection(dir);
        
        if (setEquipmentID)
        {
            if (dir == CaptoolPacket::UPLINK)
                captoolPacket->setEquipmentID(srcMac);
            else if (dir == CaptoolPacket::DOWNLINK)
                captoolPacket->setEquipmentID(dstMac);
        }
    }
    
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
ETH::describe(const CaptoolPacket *captoolPacket, std::ostream *s)
{
    assert(captoolPacket != 0);
    assert(s != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("describing packet.")
    
    struct ether_header* eth = (struct ether_header*)captoolPacket->getSegment(this, 0);

    assert(eth != 0);
    
    *s << "src: " << ether_ntoa((ether_addr*)&eth->ether_shost);
    *s << ", dst: " << ether_ntoa((ether_addr*)&eth->ether_dhost);
}
