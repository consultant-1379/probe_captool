/*
 * ServerPortSearch.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>

#include <netinet/in.h>

#include "modulemanager/ModuleManager.h"

#include "ServerPortSearch.h"
#include "flow/Flow.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

CAPTOOL_POOLABLE_INIT_POOL(ServerPort, 10000)
CAPTOOL_POOLABLE_INIT_POOL(ServerPortDescriptor, 10000)

DEFINE_CAPTOOL_MODULE(ServerPortSearch)

ServerPortSearch::ServerPortSearch(string name)
    : Module(name)
{
}

ServerPortSearch::~ServerPortSearch()
{
}

void
ServerPortSearch::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    // Query sigId
    _sigId = ClassificationMetadata::getInstance().getClassifierId("server-port-search");

    _serverPortList.setTimeout((time_t) 120); // default timeout
    if (config->exists("captool.modules." + _name))
        configure(config->lookup("captool.modules." + _name));
}

void
ServerPortSearch::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    unsigned timeout;
    if (cfg.lookupValue("timeout", timeout))
    {
        CAPTOOL_MODULE_LOG_CONFIG("server port entries time out after " << timeout << "s inactivity.")
        _serverPortList.setTimeout((time_t) timeout);
    }
}

Module*
ServerPortSearch::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")
    
    Flow * flow = captoolPacket->getFlow().get();
    if (!flow || !flow->getID()->isSet())
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }
    const FlowID::Ptr fid = flow->getID();

    // Skip 80, 8008, 8080 and 8081 ports, because multiple services can be offered on the same serverport (even worse for proxies)
    if (fid->getDestinationPort() == htons(80) || fid->getDestinationPort() == htons(8080) || fid->getSourcePort() == htons(80) || fid->getSourcePort() == htons(8080) ||
        fid->getDestinationPort() == htons(8008) || fid->getDestinationPort() == htons(8081) || fid->getSourcePort() == htons(8008) || fid->getSourcePort() == htons(8081))
    {
        return _outDefault;
    }
    
    ServerPort sp1(fid->getSourceIP()->getRawAddress(), fid->getSourcePort(), fid->getProtocol());
    ServerPort sp2(fid->getDestinationIP()->getRawAddress(), fid->getDestinationPort(), fid->getProtocol());

    // Find server port entry for source port
    boost::shared_ptr<ServerPortDescriptor> spd = _serverPortList.get(sp1);
    if (spd.get() != 0)
    {
        for (set<unsigned>::const_iterator it = spd->_blockIds.begin(); it != spd->_blockIds.end(); ++it)
        {
            flow->setHint(*it, _sigId);
        }
    }
    // Find server port entry for destination port
    spd = _serverPortList.get(sp2);
    if (spd.get() != 0)
    {
        for (set<unsigned>::const_iterator it = spd->_blockIds.begin(); it != spd->_blockIds.end(); ++it)
        {
            flow->setHint(*it, _sigId);
        }
    }

    // Update old or register new server port entries
    // Only rely on flows classified as final and having packets in both directions (in order to filter scanning activity)
    if (flow->isFinal() && flow->getUploadPackets() > 0 && flow->getDownloadPackets() > 0)
    {
        const struct timeval timestamp = captoolPacket->getPcapHeader()->ts;

        // Remove timed out server port entries
        _serverPortList.cleanup(&timestamp);
    
        // Insert or update server port entry for source port
        boost::shared_ptr<ServerPortDescriptor> spd1 = _serverPortList.get(sp1);
        if (spd1.get() == 0)
        {
            spd1 = boost::shared_ptr<ServerPortDescriptor>(new ServerPortDescriptor(timestamp, flow->getFinalBlockIds()));
            _serverPortList.insert(sp1, spd1);
        }
        else
        {
            spd1->_timestamp = timestamp;
            // TBD: verify and issue warning when new final block ID set conflicts with the previous one
            spd1->_blockIds = flow->getFinalBlockIds();
            _serverPortList.moveToEnd(sp1);
        }
        
        // Insert or update server port entry for destination port
        boost::shared_ptr<ServerPortDescriptor> spd2 = _serverPortList.get(sp2);
        if (spd2.get() == 0)
        {
            spd2 = boost::shared_ptr<ServerPortDescriptor>(new ServerPortDescriptor(timestamp, flow->getFinalBlockIds()));
            _serverPortList.insert(sp2, spd2);
        }
        else
        {
            spd2->_timestamp = timestamp;
            // TBD: verify issue warning when new final block ID set conflicts with the previous one
            spd2->_blockIds = flow->getFinalBlockIds();
            _serverPortList.moveToEnd(sp2);
        }
    }

    return _outDefault;
}

void
ServerPortSearch::getStatus(std::ostream * s, u_long, u_int)
{
    *s << "Active server-port entries: " << _serverPortList.size();
}
