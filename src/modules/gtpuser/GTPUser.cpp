/*
 * GTPUser.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>
#include <sstream>
#include <arpa/inet.h>

#include "modulemanager/ModuleManager.h"
#include "userid/IMSI.h"
#include "modules/gtpcontrol/PDPContext.h"
#include "GTPUser.h"

using std::dec;
using std::hex;
using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(GTPUser)

GTPUser::GTPUser(string name)
    : Module(name),
      _gsnIPModule(0),
      _gtpControlModule(0),
      _connections(0),
      _connectionsLength(0)
{
}

GTPUser::~GTPUser()
{
    delete[] (_connections);
}

void
GTPUser::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);

    string tmp;
    // get gsn ip module
    if (!config->lookupValue("captool.modules." + _name + ".gsnIPModule", tmp))
    {
        CAPTOOL_MODULE_LOG_WARNING("gsnIPModule not set. Unable to do imsi filtering.")
    }
    else
    {
        _gsnIPModule = static_cast<IP *>( ModuleManager::getInstance()->getModule(tmp) );
        if (_gsnIPModule == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("gsnIPModule not found. Discarding. Unable to do imsi filtering.")
        }
    }    

    // get gtp control module
    if (!config->lookupValue("captool.modules." + _name + ".gtpControlModule", tmp))
    {
        CAPTOOL_MODULE_LOG_CONFIG("gtpControlModule not set. Unable to do imsi filtering.")
    }
    else
    {
        _gtpControlModule = static_cast<GTPControl *>( ModuleManager::getInstance()->getModule(tmp) );
        if (_gtpControlModule == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("gtpControlModule not found. Discarding. Unable to do imsi filtering.")
        }
    }    
    
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
        
        int type = connection[0];
        
        if (type < 0 || type > 255)
        {
            CAPTOOL_MODULE_LOG_SEVERE("type number must be between 0 and 255.")
            exit(-1);
        }
        
        string moduleName = connection[1];
        Module *module = ModuleManager::getInstance()->getModule(moduleName);
        if (module == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
            exit(-1);
        }

        _connections[_connectionsLength].type = type;
        _connections[_connectionsLength].module = module;
        ++_connectionsLength;
        
    }
}

Module*
GTPUser::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    size_t payloadLength;
    struct gtp_header* gtp = (struct gtp_header*)captoolPacket->getPayload(&payloadLength);

    assert(gtp != 0);

    if ((gtp->flags & GTP_VER_MASK) == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("gtp version 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }
    
    // find header length
    u_int headLength = (gtp->flags & GTP_OPTS_MASK) ? 
        GTP_HEADER_CORE_WITH_OPTS_LENGTH :
        GTP_HEADER_CORE_LENGTH;

    // iterate through extension headers
    if (gtp->flags & GTP_EXT_MASK)
    {
        const u_int8_t* begin = ((const u_int8_t*)gtp) + headLength;
        //recursively parse next extension headers
        bool next = true;
        u_int8_t extLength = 0;
        while (next)
        {
            if (begin - (u_int8_t*)gtp >= static_cast<int>(payloadLength))
            {
                CAPTOOL_MODULE_LOG_WARNING("Invalid GTP-U header, dropping packet. (no. " << captoolPacket->getPacketNumber() << ")" )
                return NULL;
            }
            next = parseNextExt(begin, &extLength);
            begin += extLength;
            headLength += extLength;
        }
    }

    if (payloadLength < headLength)
    {
        CAPTOOL_MODULE_LOG_INFO("payload is too short for a GTP-U header. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }

    // save protocol header
    captoolPacket->saveSegment(this, headLength);

    // associate imsi and determine packet direction
    if (_gsnIPModule != 0 && _gtpControlModule != 0 && gtp->teid != 0)
    {
        const IPAddress::Ptr & gsnIPSrc = _gsnIPModule->getSourceIPAddressFrom(captoolPacket);
        const IPAddress::Ptr & gsnIPDst = _gsnIPModule->getDestinationIPAddressFrom(captoolPacket);

        if (gsnIPDst && gsnIPSrc)
        {
            GTPControl::NodeFunctionality srcGsnFunctionality = _gtpControlModule->getNodeFunctionality(gsnIPSrc);
            GTPControl::NodeFunctionality dstGsnFunctionality = _gtpControlModule->getNodeFunctionality(gsnIPDst);
            
            // Determine packet direction
            if (srcGsnFunctionality == GTPControl::SGSN && dstGsnFunctionality == GTPControl::SGSN)
            {
                CAPTOOL_MODULE_LOG_WARNING("Cannot determine direction of packet (no. " << captoolPacket->getPacketNumber() << "). Both endpoints of the GTP tunnel were identified as SGSNs");
            }
            else if (srcGsnFunctionality == GTPControl::GGSN && dstGsnFunctionality == GTPControl::GGSN)
            {
                CAPTOOL_MODULE_LOG_WARNING("Cannot determine direction of packet (no. " << captoolPacket->getPacketNumber() << "). Both endpoints of the GTP tunnel were identified as GGSNs");
            }
            else 
            {
                if (srcGsnFunctionality == GTPControl::SGSN || dstGsnFunctionality == GTPControl::GGSN)
                {
                    captoolPacket->setDirection(CaptoolPacket::UPLINK);
                }
                else if (srcGsnFunctionality == GTPControl::GGSN || dstGsnFunctionality == GTPControl::SGSN)
                {
                    captoolPacket->setDirection(CaptoolPacket::DOWNLINK);
                }
                else 
                {
                    CAPTOOL_MODULE_LOG_INFO("Direction for packet no. " << captoolPacket->getPacketNumber() << " cannot be determined (GSN IPs not yet knwon)")
                }
            }
            
            // Associate IMSI and IMEI to packet
            PDPConnection conn(gtp->teid, gsnIPDst);
            const PDPContext *pdp = _gtpControlModule->updatePDPContext(&conn, captoolPacket->getPcapHeader()->ts);
            if (pdp != 0)
            {
                captoolPacket->setUserID(pdp->getIMSI());
                captoolPacket->setEquipmentID(pdp->getIMEI());
            }
        }
        else
        {
            CAPTOOL_MODULE_LOG_WARNING("unable to find gsn IP address. (no. " << captoolPacket->getPacketNumber() << ")")
        }
    }

    // forward
    for (u_int i=0; i<_connectionsLength; ++i)
    {
        if (_connections[i].type == gtp->type)
        {
            return _connections[i].module;
        }
    }
    
    return _outDefault;
}

void
GTPUser::describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s)
{
    assert(captoolPacket != 0);
    assert(s != 0);

    CAPTOOL_MODULE_LOG_FINEST("processing packet.")
    
    struct gtp_header* gtp = (struct gtp_header*)captoolPacket->getSegment(this, 0);
    
    assert(gtp != 0);
    
    bool prot = gtp->flags & GTP_PROT_MASK;
    bool ext = gtp->flags & GTP_EXT_MASK;
    bool seq = gtp->flags & GTP_SEQ_MASK;
    bool npdu = gtp->flags & GTP_NPDU_MASK;

    u_int headLength = GTP_HEADER_CORE_LENGTH;
    
    if (ext || seq || npdu)
    {
        headLength += GTP_HEADER_OPTS_LENGTH;

        if (ext)
        {
            const u_char* begin = ((const u_char*)gtp) + headLength;
            //recursively parse next extension headers
            bool next = true;
            u_int8_t extLength = 0;
            while (next)
            {
                next = parseNextExt(begin, &extLength);
                begin += extLength;
                headLength += extLength;
            }
        }
    }
    
    *s << "ver: " << hex << ((gtp->flags & GTP_VER_MASK) >> 5) << dec
      << ", prot: " << prot
      << ", ext: " << ext
      << ", seq: " << seq
      << ", npdu: " << npdu
      << ", type: " << (int)(gtp->type)
      << ", tlght: " << ntohs(gtp->length)
      << ", TEID: " << hex << ntohl(gtp->teid);
}
