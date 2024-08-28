/*
 * FlowOutputStrict.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <iostream>

#include <cassert>
#include <sstream>

#include "modulemanager/ModuleManager.h"
#include "modules/eth/ETH.h"
#include "modules/gtpcontrol/PDPContext.h"

#include "flow/Flow.h"

#include "FlowOutputStrict.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(FlowOutputStrict)

FlowOutputStrict::FlowOutputStrict(string name)
    : FlowModule<Flow,FlowIDEqualsStrict>(name),
    _gtpControlModule(0),
    _userIdentifiedBytes(0),
    _equipmentIdentifiedBytes(0),
    _3GDTHackBytes(0),
    _3GDTHack(false)
{
}

FlowOutputStrict::~FlowOutputStrict()
{
}

void
FlowOutputStrict::initialize(libconfig::Config* config)
{
    FlowModule<Flow,FlowIDEqualsStrict>::initialize(config);
    
    // get GTP control module
    string tmp;
    if (!config->lookupValue("captool.modules." + _name + ".gtpControlModule", tmp))
    {
        CAPTOOL_MODULE_LOG_CONFIG("gtpControlModule not set. Unable to do imsi mapping.")
    }
    else
    {
        _gtpControlModule = static_cast<GTPControl *>( ModuleManager::getInstance()->getModule(tmp) );
        if (_gtpControlModule == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("gtpControlModule not found. Discarding. Unable to do imsi mapping.")
        }
    }

    // Check whether IP-based IMSI and IMEI assignment hack should be activited
    if (config->lookupValue("captool.modules." + _name + ".directTunnelHack", _3GDTHack) && _3GDTHack)
    {
        if (_gtpControlModule)
        {
            CAPTOOL_MODULE_LOG_WARNING("Activating 3GDTHack for unfortunate 3GDT configs (see documentation in config). This may slightly reduce performance")
        }
        else
        {
            CAPTOOL_MODULE_LOG_SEVERE("3GDTHack turned on in config but gtpControlModule not set!")
            exit(-1);
        }
    }
}

void
FlowOutputStrict::preprocess(CaptoolPacket* captoolPacket, FlowID::Ptr flowid) throw(DirectionUnknownException)
{
    CaptoolPacket::Direction dir = captoolPacket->getDirection();
    if (dir == CaptoolPacket::DOWNLINK)
    {
        flowid->swap();
    }
    else if (dir != CaptoolPacket::UPLINK)
    {
        /* 
         *   Packet direction can be set either by the ETH or the GTPUser modules
         *   Problems can occur in the following cases:
         *       1) There is no GTPC traffic or the GTPControl module is missing
         *       2) There is a GTPControl module and GTPC traffic is also captured, 
         *          but no control traffic has been seen so far from the given SGSN/GGSN
         *          (at the beginning of the measurement)
         *       3) No gateway MACs file specified for the ETH module or some gateway MACs
         *          are missing from this list
         */
        throw DirectionUnknownException();
    }
}

void
FlowOutputStrict::postprocess(CaptoolPacket* captoolPacket, Flow::Ptr flow)
{
    u_int length = captoolPacket->getSegmentsTotalLength(_baseModule);

    // Assign user and equipment ID to packet if this could not be done previously based on TEID by the GTPUser module
    if (_3GDTHack && !captoolPacket->getUserID())
    {
        FlowID::Ptr fid = flow->getID();
        const PDPContext *context = _gtpControlModule->updatePDPContext(fid->getSourceIP(), captoolPacket->getPcapHeader()->ts);
        if (context != 0)
        {
            captoolPacket->setUserID(context->getIMSI());
            captoolPacket->setEquipmentID(context->getIMEI());
            _3GDTHackBytes += length;
        }
    }

    if (flow->getUploadPackets() + flow->getDownloadPackets() == 1)
    {
        // First packet of flow, set user and equipment ID
        ID::Ptr id = captoolPacket->getUserID();
        if (id)
            flow->setUserID(id);
        id = captoolPacket->getEquipmentID();
        if (id)
            flow->setEquipmentID(id);
    }
    
    // Update flow statistics
    if (captoolPacket->getEquipmentID())
    {
        _equipmentIdentifiedBytes += length;
    }
    if (captoolPacket->getUserID())
    {
        _userIdentifiedBytes += length;
    }
}

bool
FlowOutputStrict::isUplink(CaptoolPacket* captoolPacket, Flow::Ptr)
{
    // At this point, direction can only be uplink or downlink (packets with undefined direction should have been already filtered out)
    return captoolPacket->getDirection() == CaptoolPacket::UPLINK;
}


void
FlowOutputStrict::getStatus(std::ostream *s, u_long, u_int)
{
    *s << _flows.size() << " active flows, "
    << _totalBytes << " Bytes processed during period, "
    << (_droppedBytes * 100.0 / _totalBytes) << "% dropped, "
    << (_userIdentifiedBytes * 100.0 / _totalBytes) << "% with user ID, "
    << (_equipmentIdentifiedBytes * 100.0 / _totalBytes) << "% with equipement ID";
    
    if (_3GDTHack)
        *s << ", identified via user IP: " << (_3GDTHackBytes * 100.0 / _totalBytes) << "%";
    
    // Reset counters
    _totalBytes = 0;
    _droppedBytes = 0;
    _userIdentifiedBytes = 0;
    _equipmentIdentifiedBytes = 0;
    _3GDTHackBytes = 0;
}

void
FlowOutputStrict::openNewFiles()
{
    if (!_outputEnabled) 
    {
        return;
    }

    FlowModule<Flow,FlowIDEqualsStrict>::openNewFiles();
    string statsExtension = _detailedStatistics ? "|avgPktSizeUL|avgPktSizeDL|devPktSizeUL|devPktSizeDL|avgPktIatUL|avgPktIatDL|devPktIatUL|devPktIatDL" : "";
    _fileStream << "# start|end|transport|subscriber_IP|subscriber_port|peer_IP|peer_port|packets_sent|packets_received|bytes_sent|bytes_received" << statsExtension << "|user_ID|equipement_ID|classification_tags|options...\n";
}
