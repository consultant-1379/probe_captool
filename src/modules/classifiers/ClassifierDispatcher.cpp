/*
 * ClassifierDispatcher.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>
#include <sstream>

#include "modulemanager/ModuleManager.h"

#include "ClassifierDispatcher.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(ClassifierDispatcher)

const string ClassifierDispatcher::NON_UDP_TCP_FIRST_PACKET_CONNECTION_NAME("nonUdpTcpFirstPacket");
const string ClassifierDispatcher::NON_UDP_TCP_CONNECTION_NAME("nonUdpTcp");
const string ClassifierDispatcher::CLASSIFIED_CONNECTION_NAME("classified");
const string ClassifierDispatcher::RECHECK_CONNECTION_NAME("recheck");
const string ClassifierDispatcher::UNCLASSIFIED_CONNECTION_NAME("unclassified");
const string ClassifierDispatcher::FIRST_FINAL_PACKET_CONNECTION_NAME("firstFinal");
const string ClassifierDispatcher::FIRST_REPLY_PACKET_CONNECTION_NAME("firstReply");
const string ClassifierDispatcher::FIRST_PACKET_CONNECTION_NAME("firstPacket");

ClassifierDispatcher::ClassifierDispatcher(string name)
    : Module(name),
      _minPackets(10),
      _maxPackets(40),
      _recheckFrequency(1000),
      _outNonUdpTcpFirstPacket(0),
      _outNonUdpTcp(0),
      _outClassified(0),
      _outUnclassified(0),
      _outRecheck(0),
      _outFirstFinalPacket(0),
      _outFirstReplyPacket(0),
      _outFirstPacket(0)
{
}

ClassifierDispatcher::~ClassifierDispatcher()
{
}

void
ClassifierDispatcher::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    /* configure connections */
    libconfig::Setting& connectionSettings = config->lookup("captool.modules." + _name + ".connections");
    
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
        if (connection[0].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("firt element in list no. " << i << " is not a string.")
            exit(-1);
        }
        
        if (connection[1].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("second element in list no. " << i << " is not a string.")
            exit(-1);
        }
        
        if (ClassifierDispatcher::NON_UDP_TCP_FIRST_PACKET_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outNonUdpTcpFirstPacket = ModuleManager::getInstance()->getModule(moduleName);
            if (_outNonUdpTcpFirstPacket == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (ClassifierDispatcher::NON_UDP_TCP_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outNonUdpTcp = ModuleManager::getInstance()->getModule(moduleName);
            if (_outNonUdpTcp == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (ClassifierDispatcher::CLASSIFIED_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outClassified = ModuleManager::getInstance()->getModule(moduleName);
            if (_outClassified == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (ClassifierDispatcher::RECHECK_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outRecheck = ModuleManager::getInstance()->getModule(moduleName);
            if (_outRecheck == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (ClassifierDispatcher::UNCLASSIFIED_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outUnclassified = ModuleManager::getInstance()->getModule(moduleName);
            if (_outUnclassified == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (ClassifierDispatcher::FIRST_PACKET_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outFirstPacket = ModuleManager::getInstance()->getModule(moduleName);
            if (_outFirstPacket == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (ClassifierDispatcher::FIRST_REPLY_PACKET_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outFirstReplyPacket = ModuleManager::getInstance()->getModule(moduleName);
            if (_outFirstReplyPacket == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (ClassifierDispatcher::FIRST_FINAL_PACKET_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outFirstFinalPacket = ModuleManager::getInstance()->getModule(moduleName);
            if (_outFirstFinalPacket == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        CAPTOOL_MODULE_LOG_SEVERE("connection name must be classified, unclassified, firstPacket, firstReply, firstFinal or recheck (or default)");
        exit(-1);
    }
    
    if (config->exists("captool.modules." + _name))
        configure(config->lookup("captool.modules." + _name));
}

void
ClassifierDispatcher::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    bool a = cfg.lookupValue("minPackets", _minPackets);
    bool b = cfg.lookupValue("maxPackets", _maxPackets);
    if (a || b)
        CAPTOOL_MODULE_LOG_CONFIG("classifying between " << _minPackets << " to " << _maxPackets << " packets for each flow.")
    
    if (cfg.lookupValue("recheckFrequency", _recheckFrequency))
        CAPTOOL_MODULE_LOG_CONFIG("rechecking classification after each " << _recheckFrequency << " packets.")
}

Module*
ClassifierDispatcher::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    Flow * flow = captoolPacket->getFlow().get();
    if (!flow)
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }    

    unsigned packetNumber = captoolPacket->getFlowNumber();
    u_int8_t protocol = flow->getID()->getProtocol();

    // flows other than TCP or UDP are treated separately
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
    {
        if (_outNonUdpTcpFirstPacket && packetNumber == 1)
        {
            return _outNonUdpTcpFirstPacket;
        }
        else if (_outNonUdpTcp)
        {
            return _outNonUdpTcp;
        }
    }

    if (_outFirstPacket && packetNumber == 1)
    {
        // The very first packet of the flow
        return _outFirstPacket;
    }
    
    if (_outFirstReplyPacket &&
        ( (flow->getUploadPackets() == 1 && captoolPacket->getDirection() == CaptoolPacket::UPLINK) ||     // First uplink (reply) packet in a server/peer initiated flow (FlowOutputStrict)
          (flow->getDownloadPackets() == 1 && captoolPacket->getDirection() == CaptoolPacket::DOWNLINK) || // First downlink (reply) packet in a subscriber initiated flow (FlowOutputStrict)
          (flow->getDownloadPackets() == 1 && captoolPacket->getDirection() == CaptoolPacket::UNDEFINED_DIRECTION) ) )  // First reply packet (FlowOutput, note that when using this module, uplink = initiator, downlink = responder) 
    {
        // First reply packet in the flow
        return _outFirstReplyPacket;
    }

    if (_outFirstFinalPacket && flow->getFirstFinalClassifiedPacketNumber() + 1 == packetNumber)
    {
        // Flow has just been classified as final at the previous packet of the flow
        return _outFirstFinalPacket;
    }
    
    if (_outUnclassified && 
        (packetNumber <= _minPackets || (!flow->isFinal() && packetNumber <= _maxPackets) ) )
    {   
        // Classification still to be performed
        return _outUnclassified;
    }
    
    if (_outRecheck && packetNumber % _recheckFrequency == 1)
    {
        // Periodical recheck of classification
        return _outRecheck;
    }
    
    // Classification unnecessary or deferred (or no connections have been specified for this module)
    return _outClassified;
}

void
ClassifierDispatcher::getStatus(std::ostream *, u_long, u_int)
{
}
