/*
 * FlowOutput.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <iostream>
#include <boost/function.hpp>
#include <algorithm>
#include <cassert>

#include "modulemanager/ModuleManager.h"

#include "modules/gtpcontrol/PDPContext.h"

#include "FlowOutput.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(FlowOutput)

FlowOutput::FlowOutput(string name)
    : FlowModule<Flow,FlowIDEquals>(name)
{
}

FlowOutput::~FlowOutput()
{
}

bool
FlowOutput::isUplink(CaptoolPacket* captoolPacket, Flow::Ptr flow)
{
    return flow->getID()->isSource(captoolPacket->getFlowID().getSourceIP(), captoolPacket->getFlowID().getSourcePort());
}

void
FlowOutput::openNewFiles()
{
    if (!_outputEnabled) 
    {
        return;
    }

    FlowModule<Flow,FlowIDEquals>::openNewFiles();
    string statsExtension = _detailedStatistics ? "|avgPktSizeUL|avgPktSizeDL|devPktSizeUL|devPktSizeDL|avgPktIatUL|avgPktIatDL|devPktIatUL|devPktIatDL|" : "";
    _fileStream << "# start|end|transport|initiator_IP|initiator_port|responder_IP|responder_port|packets_sent|packets_received|bytes_sent|bytes_received" << statsExtension << "|user_ID|equipement_ID|classification_tags|options...\n";
}

void
FlowOutput::getStatus(std::ostream *s, u_long, u_int)
{
    *s << _flows.size() << " active flows";
}
