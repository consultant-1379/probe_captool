/*
 * GTPControl.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <set>

#include "modulemanager/ModuleManager.h"
#include "ip/IPAddress.h"
#include "PDPContextStatus.h"
#include "GTPControl.h"
#include "util/kernel_control.h"

using std::string;
using std::hex;
using std::dec;

using std::map;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(GTPControl)

GTPControl::GTPControl(string name)
    : Module(name),
      _gsnIPModule(0),
      _currentFileSize(0),
      _maxFileSize(2 << 26),
      _output(false),
      _anonymize(false),
      _anonymizeParanoid(false),
      _imsiKey(),
      _lastTimestamp(0),
      _pdpTimeout(0),
      _imsifilter(0)
{
}


void
GTPControl::initialize(libconfig::Config* config)
{
    assert(config != 0);

    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);

    const string mygroup = "captool.modules." + _name;
    string tmp;
    // get gsn ip module
    if (!config->lookupValue(mygroup + ".gsnIPModule", tmp))
    {
        CAPTOOL_MODULE_LOG_CONFIG("gsnIPModule not set. Unable to do imsi filtering.")
    }
    else
    {
        _gsnIPModule = static_cast<IP *>( ModuleManager::getInstance()->getModule(tmp) );
        if (_gsnIPModule == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("gsnIPModule not found. Discarding. Unable to do imsi filtering.")
        }
    }    

    // set max file size
    if (!config->lookupValue(mygroup + ".maxFileSize", _maxFileSize))
    {
        CAPTOOL_MODULE_LOG_CONFIG("maxFileSize not set, using default value (" << _maxFileSize << ").")
    }
    
    // get file prefix
    if (!config->lookupValue(mygroup + ".filePrefix", _filePrefix))
    {
        CAPTOOL_MODULE_LOG_CONFIG("filePrefix not set. PDP context output disabled.")
    }
    else
    {
        // get file postfix
        if (!config->lookupValue(mygroup + ".filePostfix", _filePostfix))
        {
            CAPTOOL_MODULE_LOG_CONFIG("filePostfix not set. PDP context output disabled.")
        }
        else
        {
            _output = true;
            openNewFiles();
            ModuleManager::getInstance()->getFileManager()->registerFileGenerator(this);
        }
    }

    // Lookup whether IDs should be anonymized or not
    config->lookupValue("captool.securityManager.anonymize", _anonymize);
    if (!_anonymize)
    {
        CAPTOOL_MODULE_LOG_WARNING("securityManager.anonymize not set, IMSIs and IMEIs will not be anonymized.")
    }

    // allow setting futher "paranoid" obfuscation by hashing IMSIs from 15 digits to 13 digits (at the expense of possible collisions!)
    // Note: this "paranoid" option is only taking into account if the "anonimize" option is also set
    if (_anonymize)
    {
        config->lookupValue("captool.securityManager.paranoid", _anonymizeParanoid);
    }
    if (_anonymizeParanoid)
    {
        CAPTOOL_MODULE_LOG_WARNING("Paranoid anonymization turned on. Multiple IMSIs might be hashed to the same anonimized IMSI")
    }
    
    if (_anonymize)
    {
        string imsiKeyLocation;
        if (!config->lookupValue("captool.securityManager.keyLocation", imsiKeyLocation))
        {
            CAPTOOL_MODULE_LOG_SEVERE("securityManager.imsiKeyLocation not set.")
            exit(-1);
        }
        
        std::ifstream imsiKeyFile;
        
        imsiKeyFile.open(imsiKeyLocation.c_str(), std::ios::in);
        if (!imsiKeyFile.good())
        {
            CAPTOOL_MODULE_LOG_SEVERE("unable to open imsi key file (" << imsiKeyLocation << ").")
            exit(-1);
        }
        
        std::string s((std::istreambuf_iterator<char>(imsiKeyFile)), std::istreambuf_iterator<char>());
        _imsiKey = s;
        
        if (_imsiKey.length() == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("unable to read imsi key from file (" << imsiKeyLocation << ").")
            exit(-1);
        }
    }
    
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));
}

void
GTPControl::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("pdpTimeout", _pdpTimeout))
    {
        if (_pdpTimeout)
            CAPTOOL_MODULE_LOG_CONFIG("PDP context time out after " << _pdpTimeout << "s.")
        else
            CAPTOOL_MODULE_LOG_WARNING("PDP context timeout is 0 (zero), stale PDP contexts will not be purged. This might cause memory problems for long measurements.")
    }

    double ratio;
    if (cfg.lookupValue("samplingRatio", ratio))
    {
        if (ratio < 0 || ratio > 1)
        {
            CAPTOOL_MODULE_LOG_WARNING("Invalid sampling ratio: " << ratio)
        }
        else
        {
            CAPTOOL_MODULE_LOG_CONFIG("Sampling ratio set to " << ratio)
            _imsifilter = new SamplingFilterProcessor(SamplingFilterProcessor::IMSI, ratio);
            
            // purge and rebuild filter in the kernel module using new filter settings
            captool_module_control("clear all");
            captool_module_control("mode accept");
            for (IPMap::iterator iter(_ipMap.begin()), end(_ipMap.end()); iter != end; ++iter)
            {
                if (_imsifilter->test(iter->second->_imsi))
                {
                    captool_module_add_ip(iter->first);
                }
            }
        }
    }
}

Module*
GTPControl::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);

    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    size_t payloadLength;
    struct gtp_header* gtp = (struct gtp_header*)captoolPacket->getPayload(&payloadLength);

    _lastTimestamp = captoolPacket->getPcapHeader()->ts.tv_sec;

    assert(gtp != 0);

    if ((gtp->flags & GTP_VER_MASK) == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("gtp version 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }

    /*
     * find header and payload length
     */

    u_int headLength = (gtp->flags & GTP_OPTS_MASK) ? 
        GTP_HEADER_CORE_WITH_OPTS_LENGTH :
        GTP_HEADER_CORE_LENGTH;

    int iesLength = ntohs(gtp->length);

    if (gtp->flags & GTP_OPTS_MASK)
    {
        iesLength -= GTP_HEADER_OPTS_LENGTH;
    }

    /*
     * iterate through extension headers
     */

    if (gtp->flags & GTP_EXT_MASK)
    {
        const u_char* begin = ((const u_int8_t*)gtp) + headLength;
        //recursively parse next extension headers
        bool next = true;
        u_int8_t extLength = 0;
        while (next)
        {
            next = parseNextExt(begin, &extLength);
            begin += extLength;
            headLength += extLength;
            iesLength -= extLength;
            if (iesLength < 0) {
                CAPTOOL_MODULE_LOG_INFO("Bad formated iesLength. (no. " << captoolPacket->getPacketNumber() << ")")
                next = false; 
                return 0;
            }
        }
    }

    if (payloadLength < headLength + iesLength)
    {
        CAPTOOL_MODULE_LOG_WARNING("payload is too short for a GTP-C header. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }

    // save whole payload
    captoolPacket->saveSegment(this, payloadLength);

    if (payloadLength == headLength)
    {
        CAPTOOL_MODULE_LOG_FINE("GTP-C header contains no IEs. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }


    // if no gsnIP is set, cannot interpret packet
    if (_gsnIPModule == 0)
    {
        return _outDefault;
    }

    u_int8_t *ie = (u_int8_t *)((u_char *)gtp + headLength);

    switch (gtp->type) {
        case MESSAGE_TYPE_CREATE_PDP_REQUEST :
        {
            if (gtp->teid == 0)
            {
                CAPTOOL_MODULE_LOG_FINER("create PDP context request (primary). (no. " << captoolPacket->getPacketNumber() << ")")
               handleCreatePDPRequestPrimary(captoolPacket, gtp, ie, iesLength);
            }
            else
            {
                CAPTOOL_MODULE_LOG_FINER("create PDP context request (secondary). (no. " << captoolPacket->getPacketNumber() << ")")
                handleCreatePDPRequestSecondary(captoolPacket, gtp, ie, iesLength);
            }   
            break;
        }
        case MESSAGE_TYPE_CREATE_PDP_RESPONSE :
        {
            CAPTOOL_MODULE_LOG_FINER("create PDP context response. (no. " << captoolPacket->getPacketNumber() << ")")
            handleCreatePDPResponse(captoolPacket, gtp, ie, iesLength);
            break;
        }
        case MESSAGE_TYPE_UPDATE_PDP_REQUEST :
        {
            if (gtp->teid != 0) {
                CAPTOOL_MODULE_LOG_FINER("update PDP context request. (no. " << captoolPacket->getPacketNumber() << ")")
                handleUpdatePDPRequest(captoolPacket, gtp, ie, iesLength);
            }
            break;
        }
        case MESSAGE_TYPE_UPDATE_PDP_RESPONSE :
        {
            CAPTOOL_MODULE_LOG_FINER("update PDP context response. (no. " << captoolPacket->getPacketNumber() << ")")
            handleUpdatePDPResponse(captoolPacket, gtp, ie, iesLength);
            break;
        }
        case MESSAGE_TYPE_DELETE_PDP_REQUEST :
        {
            CAPTOOL_MODULE_LOG_FINER("delete PDP context request. (no. " << captoolPacket->getPacketNumber() << ")")
            handleDeletePDPRequest(captoolPacket, gtp, ie, iesLength);
            break;
        }
        case MESSAGE_TYPE_DELETE_PDP_RESPONSE :
        {
            CAPTOOL_MODULE_LOG_FINER("delete PDP context response. (no. " << captoolPacket->getPacketNumber() << ")")
//            handleDeletePDPResponse(captoolPacket, gtp, ie, iesLength);
            break;
        }
        case MESSAGE_TYPE_SGSN_REQUEST :
        {
            CAPTOOL_MODULE_LOG_FINER("sgsn context update request. (no. " << captoolPacket->getPacketNumber() << ")")
//            handleSGSNRequest(captoolPacket, gtp, ie, iesLength);
            break;
        }
        case MESSAGE_TYPE_SGSN_RESPONSE :
        {
            CAPTOOL_MODULE_LOG_FINER("sgsn context update response. (no. " << captoolPacket->getPacketNumber() << ")")
            handleSGSNResponse(captoolPacket, gtp, ie, iesLength);
            break;
        }
        case MESSAGE_TYPE_SGSN_ACKNOWLEDGEMENT :
        {
            CAPTOOL_MODULE_LOG_FINER("sgsn context update acknowledgement. (no. " << captoolPacket->getPacketNumber() << ")")
//            handleSGSNAcknowledgement(captoolPacket, gtp, ie, iesLength);
            break;
        }
        default :
        {
            // this type is not interesing
            CAPTOOL_MODULE_LOG_FINER("Not processing GTPC message of type " << (int)(gtp->type) << ". (no. " << captoolPacket->getPacketNumber() << ")")
            break;
        }
    }

    return _outDefault;
}

void
GTPControl::describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s)
{
    assert(captoolPacket != 0);
    assert(s != 0);

    CAPTOOL_MODULE_LOG_FINEST("describing packet.")

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

void
GTPControl::handleCreatePDPRequestPrimary(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);

    IMSI::Ptr imsi;
    u_int32_t dataTeid = 0;
    IPAddress::Ptr dataIP;
    u_int32_t controlTeid = 0;
    IPAddress::Ptr controlIP;
    u_int8_t nsapi = 255;
    IPAddress::Ptr userIP;
    
    const u_int8_t * apn = 0;
    u_int apn_length = 0;

    IMEISV::Ptr imei;

    u_int8_t ratType = 0;
    string loc = "";

    while (ie != 0)
    {
        // parse IMSI
        if (ie[0] == IE_IMSI)
        {
            imsi = parseIMSI(ie + 1);
        }
        // parse data teid
        else if (ie[0] == IE_DATA_TEID)
        {
            dataTeid = *((u_int32_t *)(ie+1));
        }
        // parse control teid
        else if (ie[0] == IE_CONTROL_TEID)
        {
            controlTeid = *((u_int32_t *)(ie+1));
        }
        // parse nsapi // if already parsed, this is linked nsapi;
        else if (ie[0] == IE_NSAPI && nsapi == 255)
        {
            nsapi = *((u_int8_t *)(ie+1));
        }
        // parse user IP
        else if (ie[0] == IE_USER_IP && ie[1] == 0 && ie[2] == 6)
        {
            userIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+5), _anonymize));
        }
        // parse ips
        else if (ie[0] == IE_GSN_ADDRESS)
        {
            // control ip comes first
            if (!controlIP)
            {
                controlIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
            // data ip comes second
            else
            {
                dataIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
        }
        else if (ie[0] == IE_APN)
        {
            apn_length = ie[1] * 256 + ie[2];
            apn = (u_int8_t *)(ie+3);
        }
        else if (ie[0] == IE_IMEISV)
        {
            imei = parseIMEISV(ie + 3); // FIXME should I care for length = ie[1] * 256 + ie[2] ?
        }
        else if (ie[0] == IE_RAT_TYPE)
        {
            ratType = ie[3];
        }
        else if (ie[0] == IE_USER_LOCATION)
        {
            loc = parseUserLocationIE(ie);
        }

        u_int8_t *nextIE = nextInformationElement(ie, &payloadLength);
        if (nextIE == (u_int8_t *)-1)
        {
            CAPTOOL_MODULE_LOG_WARNING("unknown IE. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
            return;
        }
        ie = nextIE;
    }

    if (payloadLength != 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("payload was not parsed completely. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    if (!dataTeid || !dataIP || !controlTeid || !controlIP || nsapi == 255 || !imsi)
    {
        CAPTOOL_MODULE_LOG_WARNING("invalid create PDP context request. Cannot read data or control plane info or nsapi or imsi. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    PDPConnection *controlConn = new PDPConnection(controlTeid, controlIP);

    // Register data IP address as an SGSN IP address
    registerNodeFunctionality(dataIP, GTPControl::SGSN);

    /*
     * check if the connection already existed
     */
    PDPContextMap::const_iterator iter = _pdpControlMap.find(controlConn);
    if (iter != _pdpControlMap.end())
    {
        PDPContext *pdp = ((PDPContext *)iter->second);

        assert(pdp != 0);

        if (pdp->_status._status == PDPContextStatus::PDP_CREATE_REQUEST && pdp->_status._nsapi == nsapi)
        {
            CAPTOOL_MODULE_LOG_WARNING("create PDP context request (primary) resent. Removing existing context. (no. " << captoolPacket->getPacketNumber() << ")")
        }
        else
        {
            CAPTOOL_MODULE_LOG_WARNING("create PDP context request (primary) for already established PDP context. Removing existing context. (no. " << captoolPacket->getPacketNumber() << ")")
        }

        deletePDPContext(pdp, true, &captoolPacket->getPcapHeader()->ts);
    }

    PDPContext *context = new PDPContext(&(captoolPacket->getPcapHeader()->ts), PDPContextStatus::PDP_CREATE_REQUEST, nsapi, imsi, imei);
    if (apn != 0)
    {
        context->setAPN(apn, apn_length);
    }
    if (ratType != 0)
    {
        context->_ratType = ratType;
    }
    if (loc != "")
    {
        context->_loc = loc;
    }
    context->_control = new PDPConnections();
    context->_control->_conn1 = controlConn;

    PDPConnections *dataConns = new PDPConnections();
    dataConns->_conn1 = new PDPConnection(dataTeid, dataIP);

    context->_datas.insert(PDPContext::DataConnectionsMapPair(nsapi, dataConns));

    _pdpControlMap.insert(PDPContextMapPair(controlConn, context));
    _pdpDataMap.insert(PDPContextMapPair(dataConns->_conn1, context));
 

    if (context->_userIP == 0 && userIP != 0)    
    {
        context->_userIP = userIP;
        
        _ipMap.insert(IPMapPair(userIP, context));
        if (_imsifilter && _imsifilter->test(imsi)) 
        {
            captool_module_add_ip(userIP);
        }
    }
}

void
GTPControl::handleCreatePDPRequestSecondary(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);

    const IPAddress::Ptr & gsnIPDst = _gsnIPModule->getDestinationIPAddressFrom(captoolPacket);

    if (!gsnIPDst)
    {
        CAPTOOL_MODULE_LOG_WARNING("unable to find gsn IP address. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    u_int32_t dataTeid = 0;
    IPAddress::Ptr dataIP;
    IPAddress::Ptr controlIP;
    u_int8_t nsapi = 255;

    while (ie != 0)
    {
        // parse data teid
        if (ie[0] == IE_DATA_TEID)
        {
            dataTeid = *((u_int32_t *)(ie+1));
        }
        // parse nsapi // if already parsed, this is linked nsapi;
        else if (ie[0] == IE_NSAPI && nsapi == 255)
        {
            nsapi = *((u_int8_t *)(ie+1));
        }
        // parse ips
        else if (ie[0] == IE_GSN_ADDRESS)
        {
            // control ip comes first
            if (!controlIP)
            {
                controlIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
            // data ip comes second
            else
            {
                dataIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
        }

        u_int8_t *nextIE = nextInformationElement(ie, &payloadLength);
        if (nextIE == (u_int8_t *)-1)
        {
            CAPTOOL_MODULE_LOG_WARNING("unknown IE. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
            return;
        }
        ie = nextIE;
    }

    if (payloadLength != 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("payload was not parsed completely. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    if (!dataTeid || !dataIP || nsapi == 255)
    {
        CAPTOOL_MODULE_LOG_WARNING("invalid create PDP context request (secondary). Cannot read data plane info. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }


    // find associated PDPContext
    PDPConnection key(gtp->teid, gsnIPDst);
    PDPContextMap::const_iterator iter = _pdpControlMap.find(&key);

    if (iter == _pdpControlMap.end())
    {
        CAPTOOL_MODULE_LOG_WARNING("create PDP context request (secondary) for non-existing context. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    PDPContext *context = (PDPContext *)iter->second;

    assert(context != 0);

    if (!context->isEstablished())
    {
        CAPTOOL_MODULE_LOG_WARNING("create PDP context request (secondary) for non-established context. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    // Register data IP address as an SGSN IP address
    registerNodeFunctionality(dataIP, GTPControl::SGSN);

    PDPConnections *dataConns = new PDPConnections();
    PDPConnection *dataConn = new PDPConnection(dataTeid, dataIP);

    // assign dataConn to correct GSN
    if (context->_control->_conn2 != 0 && key.equals(context->_control->_conn2))
    {
        if (dataConns->_conn1 != 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("create PDP context request for already existing PDPConnection. (no. " << captoolPacket->getPacketNumber() << ")")
            delete(dataConns->_conn1);
        }
        dataConns->_conn1 = dataConn;
    }
    else if (context->_control->_conn1 != 0 && key.equals(context->_control->_conn1))
    {
        if (dataConns->_conn2 != 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("create PDP context request for already existing PDPConnection. (no. " << captoolPacket->getPacketNumber() << ")")
            delete(dataConns->_conn2);
        }
        dataConns->_conn2 = dataConn;
    }
    else
    {
        CAPTOOL_MODULE_LOG_WARNING("create PDP context request (secondary) with wrong control teid ?! Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")

        delete(dataConns);
        delete(dataConn);
        return;
    }

    context->_datas.insert(PDPContext::DataConnectionsMapPair(nsapi, dataConns));

    _pdpDataMap.insert(PDPContextMapPair(dataConn, context));
}


void
GTPControl::handleCreatePDPResponse(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);

    if (gtp->teid == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("create PDP context response to teid 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    const IPAddress::Ptr & gsnIPDst = _gsnIPModule->getDestinationIPAddressFrom(captoolPacket);

    if (!gsnIPDst)
    {
        CAPTOOL_MODULE_LOG_WARNING("unable to find gsn IP address. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    // find control connection
    PDPConnection key(gtp->teid, gsnIPDst);
    PDPContextMap::const_iterator iter = _pdpControlMap.find(&key);

    if (iter == _pdpControlMap.end())
    {
        CAPTOOL_MODULE_LOG_WARNING("create PDP context reply for non-existing context. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    PDPContext *context = (PDPContext *)(iter->second);

    assert(context != 0);
    assert(context->_control != 0);

    if (context->_status._status != PDPContextStatus::PDP_CREATE_REQUEST)
    {
        CAPTOOL_MODULE_LOG_WARNING("create PDP context response for already created context. Dropping Packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    u_int32_t dataTeid = 0;
    IPAddress::Ptr dataIP;
    u_int32_t controlTeid = 0;
    IPAddress::Ptr controlIP;
    u_int8_t  cause = 255; // reserved for gtp' only
    IPAddress::Ptr userIP;

    while (ie != 0)
    {
        // parse cause
        if (ie[0] == IE_CAUSE)
        {
            cause = *((u_int8_t *)(ie+1));
        }
        // parse data teid
        else if (ie[0] == IE_DATA_TEID)
        {
            dataTeid = *((u_int32_t *)(ie+1));
        }
        // parse control teid
        else if (ie[0] == IE_CONTROL_TEID)
        {
            controlTeid = *((u_int32_t *)(ie+1));
        }
        // parse user IP
        else if (ie[0] == IE_USER_IP && ie[1] == 0 && ie[2] == 6)
        {
            userIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+5), _anonymize));
        }
        // parse ips
        else if (ie[0] == IE_GSN_ADDRESS)
        {
            // control ip comes first
            if (!controlIP)
            {
                controlIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
            // data ip comes second
            else
            {
                dataIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
        }


        u_int8_t *nextIE = nextInformationElement(ie, &payloadLength);
        if (nextIE == (u_int8_t *)-1)
        {
            CAPTOOL_MODULE_LOG_WARNING("unknown IE. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
            return;
        }
        ie = nextIE;
    }


    if (payloadLength != 0)
    {
        CAPTOOL_MODULE_LOG_INFO("payload was not parsed completely. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    // not accepted
    if (cause != 128)
    {
        CAPTOOL_MODULE_LOG_INFO("create request rejected. (no. " << captoolPacket->getPacketNumber() << ")")

        // remove other half of create
        if (context->_status._status == PDPContextStatus::PDP_CREATE_REQUEST)
        {
            // remove whole context if primary is being created
            if (context->_primaryNsapi == context->_status._nsapi)
            {
                CAPTOOL_MODULE_LOG_FINE("deleting context")
                deletePDPContext(context, false, 0);
                return;
            }
            // remove the secondary PDP that is being created
            else
            {
                PDPContext::DataConnectionsMap::const_iterator iter2 = context->_datas.find(context->_status._nsapi);
                if (iter2 == context->_datas.end())                        
                {
                    CAPTOOL_MODULE_LOG_WARNING("unable to find secondary pdp context to remove")
                }
                else
                {
                    CAPTOOL_MODULE_LOG_FINE("removing secondary pdp context")
                    PDPConnections *dataConns = (PDPConnections *)iter2->second;
                    if (dataConns->_conn1 != 0)
                    {
                        _pdpDataMap.erase(dataConns->_conn1);
                    }
                    if (dataConns->_conn2 != 0)
                    {
                        _pdpDataMap.erase(dataConns->_conn2);
                    }
                    context->_datas.erase(context->_status._nsapi);
                    delete(dataConns);
                }
            }
        }

        return;
    }

    if (dataTeid == 0 || !dataIP)
    {
        CAPTOOL_MODULE_LOG_WARNING("invalid create PDP context response. Cannot read data plane info. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    if (controlTeid && controlIP)
    {
        if (context->_primaryNsapi != context->_status._nsapi)
        {
            CAPTOOL_MODULE_LOG_WARNING("create PDP context response with control TEID to non-primary PDP context. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
            return;
        }

        // response to primary request

        if (context->isEstablished())
        {
            CAPTOOL_MODULE_LOG_WARNING("create PDP context response for already established context. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
            return;
        }

        context->_control->_conn2 = new PDPConnection(controlTeid, controlIP);
        context->_status._status = PDPContextStatus::OK;
        _pdpControlMap.insert(PDPContextMapPair(context->_control->_conn2, context));

    }

    // get data, (the one with the same nsapi)
    PDPContext::DataConnectionsMap::const_iterator iter3 = context->_datas.find(context->_status._nsapi);

    if (iter3 == context->_datas.end())
    {
        CAPTOOL_MODULE_LOG_WARNING("cannot find PDP context data plane for response. Dropping context. (no. " << captoolPacket->getPacketNumber() << ")")
        deletePDPContext(context, false, 0);
        return;
    }

    // Register data IP address as a GGSN IP address
    registerNodeFunctionality(dataIP, GTPControl::GGSN);

    PDPConnections *dataConns = (PDPConnections *)iter3->second;
    PDPConnection *dataConn = new PDPConnection(dataTeid, dataIP);

    // assign dataConn to correct GSN (if sent to conn1's teid, its data2, or vica versa)
    if (context->_control->_conn2 != 0 && key.equals(context->_control->_conn2))
    {
        if (dataConns->_conn1 != 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("create PDP context response for already existing PDPConnection. (no. " << captoolPacket->getPacketNumber() << ")")
            _pdpDataMap.erase(dataConns->_conn1);
            delete(dataConns->_conn1);
        }
        dataConns->_conn1 = dataConn;
        _pdpDataMap.insert(PDPContextMapPair(dataConn, context));
    }
    else if (context->_control->_conn1 != 0 && key.equals(context->_control->_conn1))
    {
        if (dataConns->_conn2 != 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("create PDP context response for already existing PDPConnection. (no. " << captoolPacket->getPacketNumber() << ")")
            _pdpDataMap.erase(dataConns->_conn2);
            delete(dataConns->_conn2);
        }
        dataConns->_conn2 = dataConn;
        _pdpDataMap.insert(PDPContextMapPair(dataConn, context));

    }
    else
    {
        CAPTOOL_MODULE_LOG_WARNING("create PDP context response (secondary) with wrong control teid ?! Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        delete(dataConns);
        delete(dataConn);
        return;
    }

    if (userIP)
    {
        context->_userIP = userIP;
        
        // Verify whether a stale context is registered for this IP (e.g. when corresponding delete PDP Context messsages were dropped)
        IPMap::const_iterator it = _ipMap.find(userIP);
        if (it != _ipMap.end() && it->second != context)
        {
            // If another (stale) context is registered for this IP, than delete it first
            deletePDPContext(it->second, true, NULL);
            CAPTOOL_MODULE_LOG_WARNING("Deleting stale context for " << userIP << " (delete PDP context messages were probably dropped)")
        }
        
        _ipMap.insert(IPMapPair(userIP, context));
        if (_imsifilter && _imsifilter->test(context->_imsi)) 
        {
            captool_module_add_ip(userIP);
        }
    }

    context->_status._status = PDPContextStatus::OK;
}


void
GTPControl::handleUpdatePDPRequest(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);

    if (gtp->teid == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("update PDP context request to teid 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    const IPAddress::Ptr & gsnIPDst = _gsnIPModule->getDestinationIPAddressFrom(captoolPacket);

    if (!gsnIPDst)
    {
        CAPTOOL_MODULE_LOG_WARNING("unable to find gsn IP address. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    // find context
    PDPConnection key(gtp->teid, gsnIPDst);
    PDPContextMap::const_iterator iter = _pdpControlMap.find(&key);

    if (iter == _pdpControlMap.end())
    {
        // Frequent event in 3GDT configs where only a few RNCs are monitored but we have the complete GTP-C traffic from Gn
        CAPTOOL_MODULE_LOG_INFO("update PDP context request for non-existing context. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    PDPContext *context = (PDPContext *)iter->second;

    assert(context != 0);

    if (context->_status._status == PDPContextStatus::PDP_CREATE_REQUEST)
    {
        CAPTOOL_MODULE_LOG_INFO("update PDP context request for context under create. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    if (context->_status._status == PDPContextStatus::PDP_UPDATE_REQUEST)
    {
        CAPTOOL_MODULE_LOG_INFO("update PDP context request for context under update. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    u_int32_t dataTeid = 0;
    IPAddress::Ptr dataIP;
    u_int32_t controlTeid = 0;
    IPAddress::Ptr controlIP;
    u_int8_t nsapi = 255;

    while (ie != 0)
    {
        // parse data teid
        if (ie[0] == IE_DATA_TEID)
        {
            dataTeid = *((u_int32_t *)(ie+1));
        }
        // parse control teid
        else if (ie[0] == IE_CONTROL_TEID)
        {
            controlTeid = *((u_int32_t *)(ie+1));
        }
        // parse nsapi // if already parsed, this is linked nsapi;
        else if (ie[0] == IE_NSAPI && nsapi == 255)
        {
            nsapi = *((u_int8_t *)(ie+1));
        }
        // parse ips
        else if (ie[0] == IE_GSN_ADDRESS)
        {
            // control ip comes first
            if (!controlIP)
            {
                controlIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
            // data ip comes second
            else
            {
                dataIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
        }


        u_int8_t *nextIE = nextInformationElement(ie, &payloadLength);
        if (nextIE == (u_int8_t *)-1)
        {
            CAPTOOL_MODULE_LOG_WARNING("unknown IE. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
            return;
        }
        ie = nextIE;
    }

    if (payloadLength != 0)
    {
        CAPTOOL_MODULE_LOG_INFO("payload was not parsed completely. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    if (dataTeid == 0 || !dataIP || nsapi == 255)
    {
        // ggsn initiated request contains these fields optionally only
        CAPTOOL_MODULE_LOG_FINE("create PDP context contains no teids. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    if (controlTeid != 0 && controlIP)
    {
        if (nsapi != context->_primaryNsapi)
        {
            CAPTOOL_MODULE_LOG_WARNING("update pdp request with control teid update and no primary nsapi. (no. " << captoolPacket->getPacketNumber() << ")")
        }

        PDPConnection *controlConn = new PDPConnection(controlTeid, controlIP);

        // update the control conn that is not the one this msg was sent to
        if (context->_control->_conn2 != 0 && key.equals(context->_control->_conn2))
        {
            if (context->_control->_conn1)
            {
                _pdpControlMap.erase(context->_control->_conn1);
                delete(context->_control->_conn1);
            }
            context->_control->_conn1 = controlConn;
            _pdpControlMap.insert(PDPContextMapPair(controlConn, context));
        }
        else if (context->_control->_conn1 != 0 && key.equals(context->_control->_conn1))
        {
            if (context->_control->_conn2)
            {
                _pdpControlMap.erase(context->_control->_conn2);
                delete(context->_control->_conn2);
            }
            context->_control->_conn2 = controlConn;
            _pdpControlMap.insert(PDPContextMapPair(controlConn, context));
        }
        else
        {
            delete controlConn;
        }
    }
    
    PDPContext::DataConnectionsMap::const_iterator iter2 = context->_datas.find(nsapi);

    if (iter2 == context->_datas.end())
    {
        CAPTOOL_MODULE_LOG_WARNING("update pdp request for non-existing nsapi. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    PDPConnections *dataConns = (PDPConnections *)iter2->second;

    assert(dataConns != 0);

    // Register data IP address as an SGSN IP address
    registerNodeFunctionality(dataIP, GTPControl::SGSN);

    PDPConnection *dataConn = new PDPConnection(dataTeid, dataIP);

    // assign dataConn to correct GSN (if sent to conn1's teid, its data2, or vica versa)
    if (context->_control->_conn2 != 0 && key.equals(context->_control->_conn2))
    {
        if (dataConns->_conn1)
        {
            _pdpDataMap.erase(dataConns->_conn1);
            delete(dataConns->_conn1);
        }
        dataConns->_conn1 = dataConn;
        _pdpDataMap.insert(PDPContextMapPair(dataConn, context));
    }
    else if (context->_control->_conn1 != 0 && key.equals(context->_control->_conn1))
    {
        if (dataConns->_conn2)
        {
            _pdpDataMap.erase(dataConns->_conn2);
            delete(dataConns->_conn2);
        }
        dataConns->_conn2 = dataConn;
        _pdpDataMap.insert(PDPContextMapPair(dataConn, context));
    }
    else
    {
        CAPTOOL_MODULE_LOG_WARNING("update PDP context request (secondary) with wrong control teid ?! Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        delete(dataConn);
        return;
    }

    context->_status._status = PDPContextStatus::PDP_UPDATE_REQUEST;
    context->_status._nsapi = nsapi;
}

void
GTPControl::handleUpdatePDPRequestVersion(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);
}

void
GTPControl::handleUpdatePDPResponse(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);

    if (gtp->teid == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("update PDP context response to teid 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    const IPAddress::Ptr & gsnIPDst = _gsnIPModule->getDestinationIPAddressFrom(captoolPacket);

    if (!gsnIPDst)
    {
        CAPTOOL_MODULE_LOG_WARNING("unable to find gsn IP address. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    // find context
    //gsnIPDst, gsnIPSrc must be copied
    PDPConnection key(gtp->teid, gsnIPDst);
    PDPContextMap::const_iterator iter = _pdpControlMap.find(&key);

    if (iter == _pdpControlMap.end())
    {
        // Frequent event in 3GDT configs where only a few RNCs are monitored but we have the complete GTP-C traffic from Gn
        CAPTOOL_MODULE_LOG_INFO("update PDP context response for non-existing context. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    PDPContext *context = (PDPContext *)iter->second;

    assert(context != 0);

    if (context->_status._status == PDPContextStatus::PDP_CREATE_REQUEST)
    {
        CAPTOOL_MODULE_LOG_INFO("update PDP context response for context under create. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    if (context->_status._status == PDPContextStatus::OK)
    {
        CAPTOOL_MODULE_LOG_INFO("update PDP context response for context not under update. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    u_int32_t dataTeid = 0;
    IPAddress::Ptr dataIP;
    u_int32_t controlTeid = 0;
    IPAddress::Ptr controlIP;

    while (ie != 0)
    {
        // parse data teid
        if (ie[0] == IE_DATA_TEID)
        {
            dataTeid = *((u_int32_t *)(ie+1));
        }
        // parse control teid
        else if (ie[0] == IE_CONTROL_TEID)
        {
            controlTeid = *((u_int32_t *)(ie+1));
        }
        // parse ips
        else if (ie[0] == IE_GSN_ADDRESS)
        {
            // control ip comes first
            if (!controlIP)
            {
                controlIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
            // data ip comes second
            else
            {
                dataIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ie+3)));
            }
        }


        u_int8_t *nextIE = nextInformationElement(ie, &payloadLength);
        if (nextIE == (u_int8_t *)-1)
        {
            CAPTOOL_MODULE_LOG_WARNING("unknown IE. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
            return;
        }
        ie = nextIE;
    }

    if (payloadLength != 0)
    {
        CAPTOOL_MODULE_LOG_INFO("payload was not parsed completely. (no. " << captoolPacket->getPacketNumber() << ")")
    }

    if (dataTeid == 0 || !dataIP)
    {
        // ggsn initiated request contains these fields optionally only
        CAPTOOL_MODULE_LOG_FINE("update PDP context contains no teids. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }


    if (controlTeid != 0 && controlIP)
    {
        if (context->_status._nsapi != context->_primaryNsapi)
        {
            CAPTOOL_MODULE_LOG_WARNING("update pdp context response with control teid for non-primary context")
        }

        PDPConnection *controlConn = new PDPConnection(controlTeid, controlIP);

        // update the control conn that is not the one this msg was sent to
        if (context->_control->_conn2 != 0 && key.equals(context->_control->_conn2))
        {
            if (context->_control->_conn1 == 0)
            {
                CAPTOOL_MODULE_LOG_WARNING("update PDP context response for non-existing control connection. (no. " << captoolPacket->getPacketNumber() << ")")
            }
            else
            {
                _pdpControlMap.erase(context->_control->_conn1);
                delete(context->_control->_conn1);
            }
            context->_control->_conn1 = controlConn;
            _pdpControlMap.insert(PDPContextMapPair(controlConn, context));
        }
        else if (context->_control->_conn1 != 0 && key.equals(context->_control->_conn1))
        {
            if (context->_control->_conn2 == 0)
            {
                CAPTOOL_MODULE_LOG_WARNING("update PDP context response for non-existing control connection. (no. " << captoolPacket->getPacketNumber() << ")")
            }
            else
            {
                _pdpControlMap.erase(context->_control->_conn2);
                delete(context->_control->_conn2);
            }
            context->_control->_conn2 = controlConn;
            _pdpControlMap.insert(PDPContextMapPair(controlConn, context));
        }
        else
        {
            delete(controlConn);
        }
    }    

    PDPContext::DataConnectionsMap::const_iterator iter2 = context->_datas.find(context->_status._nsapi);

    if (iter2 == context->_datas.end())
    {
        CAPTOOL_MODULE_LOG_WARNING("update pdp response for non-existing nsapi ?! Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    if (context->_control->_conn1 == 0 || context->_control->_conn2 == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("update pdp response for context with no control teid set. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    // Register data IP address as a GGSN IP address
    registerNodeFunctionality(dataIP, GTPControl::GGSN);

    PDPConnections *dataConns = (PDPConnections *)iter2->second;
    PDPConnection *dataConn = new PDPConnection(dataTeid, dataIP);
    assert(dataConns != 0);

    // assign dataConn to correct GSN (if sent to conn1's teid, its data2, or vica versa)
    if (context->_control->_conn2 != 0 && key.equals(context->_control->_conn2))
    {
        if (dataConns->_conn1 == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("update PDP context response for non-existing PDPConnection. (no. " << captoolPacket->getPacketNumber() << ")")
        }
        else
        {
            _pdpDataMap.erase(dataConns->_conn1);
            delete(dataConns->_conn1);
        }
        dataConns->_conn1 = dataConn;
        _pdpDataMap.insert(PDPContextMapPair(dataConn, context));
    }
    else if (context->_control->_conn1 != 0 && key.equals(context->_control->_conn1))
    {
        if (dataConns->_conn2 == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("update PDP context response for non-existing PDPConnection. (no. " << captoolPacket->getPacketNumber() << ")")
        }
        else
        {
            _pdpDataMap.erase(dataConns->_conn2);
            delete(dataConns->_conn2);
        }
        dataConns->_conn2 = dataConn;
        _pdpDataMap.insert(PDPContextMapPair(dataConn, context));
    }
    else
    {
        CAPTOOL_MODULE_LOG_WARNING("update PDP context response (secondary) with wrong control teid ?! Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        delete(dataConn);
        return;
    }

    context->_status._status = PDPContextStatus::OK;
}


void
GTPControl::handleDeletePDPRequest(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);

    if (gtp->teid == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("delete PDP context request to teid 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }
    
    const IPAddress::Ptr & gsnIPDst = _gsnIPModule->getDestinationIPAddressFrom(captoolPacket);

    if (!gsnIPDst)
    {
        CAPTOOL_MODULE_LOG_WARNING("unable to find gsn IP address. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    // find control connection
    PDPConnection key(gtp->teid, gsnIPDst);
    PDPContextMap::const_iterator iter = _pdpControlMap.find(&key);

    if (iter == _pdpControlMap.end())
    {
        CAPTOOL_MODULE_LOG_INFO("delete PDP context request for non-existing context. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }

    PDPContext *context = (PDPContext *)(iter->second);

    assert(context != 0);

    deletePDPContext(context, true, &captoolPacket->getPcapHeader()->ts);

}

void
GTPControl::handleDeletePDPResponse(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);

    if (gtp->teid == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("delete PDP context response to teid 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
    }
}

void
GTPControl::handleSGSNRequest(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);
}

void
GTPControl::handleSGSNResponse(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);

    PDPContext *context = 0; // context that will be filled up
    IMSI::Ptr imsi;

    while (ie != 0)
    {
        // parse cause
        if (ie[0] == IE_CAUSE)
        {
            u_int8_t cause = ie[1];

            if (cause != 128)
            {
                CAPTOOL_MODULE_LOG_INFO("rejected sgsn context update (no. " << captoolPacket->getPacketNumber() << ")")
                return;
            }
        }

        // parse IMSI
        else if(ie[0] == IE_IMSI)
        {
            imsi = parseIMSI(ie + 1);
        }

        // parse pdp context
        else if(ie[0] == IE_PDP_CONTEXT)
        {
            u_int8_t nsapi = 255;
            u_int32_t dataTeid = 0;
            u_int32_t controlTeid = 0;
            IPAddress::Ptr dataIP;
            IPAddress::Ptr controlIP;
            IPAddress::Ptr userIP;

            u_int8_t *ptr = (ie + 1);

            //parse nsapi
            nsapi = ptr[2] & 0x0f;

            //skip qos sub
            ptr += ptr[4] + 5;

            //skip qos req
            ptr += ptr[0] + 1;

            //skip qos neg and next elements (another 6 bytes)
            ptr += ptr[0] + 7;

            // uplink teid ctrl
            controlTeid = *((u_int32_t *)ptr);
            ptr += 4;

            // uplink teid data
            dataTeid = *((u_int32_t *)ptr);
            ptr += 7; // (also skip 3 next bytes)

            // parse user address
            userIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)(ptr + 1), _anonymize));
            
            // skip user address's length (ptr->length).
            ptr += ptr[0] + 1;

            // get gsn address control plane
            if (ptr[0] != 4)
            {
                CAPTOOL_MODULE_LOG_WARNING("not an IPv4 SGSN address. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
                return;
            }
            ++ptr;

            controlIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)ptr));
            ptr += 4;

            // get gsn address data plane
            if (ptr[0] != 4)
            {
                CAPTOOL_MODULE_LOG_WARNING("not an IPv4 SGSN address. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
                return;
            }
            ++ptr;

            dataIP = IPAddress::Ptr(new IPAddress(*(u_int32_t *)ptr));

            if ((!imsi) || controlTeid == 0 || dataTeid == 0 || !controlIP || !dataIP || nsapi == 255)
            {
                CAPTOOL_MODULE_LOG_WARNING("unable to parse PDPIE completely. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
                return;
            }

            // check if a known context is passed to another sgsn
            PDPConnection key(controlTeid, controlIP);

            PDPContextMap::const_iterator iter = _pdpControlMap.find(&key);

            if (context == 0 && iter != _pdpControlMap.end())
            {
                PDPContext *c = (PDPContext *)iter->second;

                assert(c != 0);

                if (c->_imsi != imsi)
                {
                    CAPTOOL_MODULE_LOG_WARNING("sgsn context response removed existing context with different IMSI. (no. " << captoolPacket->getPacketNumber() << ")\n"
                                               "    " << c->_imsi << " and " << imsi)
                    deletePDPContext(c, true, &captoolPacket->getPcapHeader()->ts);
                }
                else
                {
                    CAPTOOL_MODULE_LOG_FINE("sgsn context response removed existing context. (no. " << captoolPacket->getPacketNumber() << ")")
                }
                
                // TBD: check whether anything needs to be modified in the context?
                return;
            }
            else
            {
                PDPConnection *controlConn = new PDPConnection(controlTeid, controlIP);
                
                if (context != 0)
                {
                    // check if this is a secondary context of the previously created one
                    if (context->_control->_conn1->equals(controlConn))
                    {
                        // add new data conn
                        PDPConnections *dataConns = new PDPConnections();
                        PDPConnection *dataConn = new PDPConnection(dataTeid, dataIP);
                        dataConns->_conn1 = dataConn;
                        context->_datas.insert(PDPContext::DataConnectionsMapPair(nsapi, dataConns));

                        _pdpDataMap.insert(PDPContextMapPair(dataConn, context));
                    }
                    else
                    {
                        // create new context
                        context = 0;
                    }
                }
                
                if (context == 0)
                {
                    // create new context based on input
                    context = new PDPContext(&(captoolPacket->getPcapHeader()->ts), PDPContextStatus::OK, nsapi, imsi);
                    context->_control = new PDPConnections();
                    context->_control->_conn1 = controlConn;
                    context->_userIP = userIP;
                    PDPConnections *dataConns = new PDPConnections();
                    PDPConnection *dataConn = new PDPConnection(dataTeid, dataIP);
                    dataConns->_conn1 = dataConn;
                    context->_datas.insert(PDPContext::DataConnectionsMapPair(nsapi, dataConns));

                    _pdpControlMap.insert(PDPContextMapPair(controlConn, context));
                    _pdpDataMap.insert(PDPContextMapPair(dataConn, context));
                    
                    if (userIP)
                    {
                        _ipMap.insert(IPMapPair(userIP, context));
                        if (_imsifilter && _imsifilter->test(context->_imsi)) 
                        {
                            captool_module_add_ip(userIP);
                        }
                    }
                }
            }
        }




        u_int8_t *nextIE = nextInformationElement(ie, &payloadLength);
        if (nextIE == (u_int8_t *)-1)
        {
        CAPTOOL_MODULE_LOG_WARNING("unknown IE. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return;
        }
        ie = nextIE;
    }

    if (context == 0)
    {
        //no context was created
    }

}

void
GTPControl::handleSGSNAcknowledgement(CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength)
{
    assert(captoolPacket != 0);
    assert(gtp != 0);
    assert(ie != 0);
    assert(payloadLength > 0);
}

u_int8_t *
GTPControl::nextInformationElement(u_int8_t *ie, u_int *length)
{
    assert(ie != 0);
//    assert(ie[0] != 0);
    assert(length != 0);

    // is valid IE ?
    if (!_ies.isValid(ie[0]))
    {
        return (u_int8_t *)-1;
    }    

    u_int16_t ieLength;
    
    // Type-Value
    if (ie[0] <= 127)
    {
        ieLength = _ies.getLength(ie[0]) + 1;
    }
    // Type-Length-Value
    else
    {
        ieLength = ie[1] * 256 + ie[2] + 3;
    }
    
    // Invalid length
    if (ieLength > *length)
    {
        return (u_int8_t *)-1;
    }    
    
    *length -= ieLength;

    return (*length > 0) ? (ie + ieLength) : 0;

}

void
GTPControl::deletePDPContext(PDPContext *context, bool write, const struct timeval *timestamp)
{
    assert(context != 0);
    assert(context->_control != 0);

    if (write && _output)
    {
        std::streampos pos = _fileStream.tellp();
        
        _fileStream.fill('0');
        _fileStream << context->_created.tv_sec;
        _fileStream << ".";
        _fileStream.width(6);
        _fileStream << context->_created.tv_usec;
        _fileStream.width(0);
        _fileStream << "|";
        if (timestamp)
        {
            _fileStream << timestamp->tv_sec;
            _fileStream << ".";
            _fileStream.width(6);
            _fileStream << timestamp->tv_usec;
            _fileStream.width(0);
        }
        else
        {
            _fileStream << "na";
        }
        _fileStream << "|" << * context->_imsi << "|";
        _fileStream << context->_imeisv << "|";
        if (context->_userIP == 0)
        {
            _fileStream << "na";
        }
        else
        {
            _fileStream << * context->_userIP;
        }
        _fileStream << "|";
        _fileStream << context->getAPN() << "|";
        _fileStream << context->getRAT() << "|";
        _fileStream << context->_loc;
        
        _fileStream << "\n";
        
        _currentFileSize += _fileStream.tellp() - pos;

        if ( (_maxFileSize > 0) && (_currentFileSize >= _maxFileSize) )
        {
            ModuleManager::getInstance()->getFileManager()->fileSizeReached();
        }
        
    }
    
    //remove context from all mappings
    if (context->_control->_conn1 != 0)
    {
        _pdpControlMap.erase(context->_control->_conn1);
    }
    if (context->_control->_conn2 != 0)
    {
        _pdpControlMap.erase(context->_control->_conn2);
    }

    if (context->_userIP != 0)
    {
        _ipMap.erase(context->_userIP);
        captool_module_remove_ip(context->_userIP);
    }
    
    
    for (PDPContext::DataConnectionsMap::const_iterator iter(context->_datas.begin()), end(context->_datas.end()); iter != end; ++iter)
    {
        PDPConnections *conns = (PDPConnections *)iter->second;

        assert(conns != 0);

        if (conns->_conn1 != 0)
        {
            _pdpDataMap.erase(conns->_conn1);
        }
        if (conns->_conn2 != 0)
        {
            _pdpDataMap.erase(conns->_conn2);
        }
    }

    delete(context);
}

void
GTPControl::registerNodeFunctionality(const IPAddress::Ptr & ip, NodeFunctionality functionality)
{
    assert(ip);

    // Verify existance of a previous entry for the same address
    NodeFunctionality previousFunctionality = getNodeFunctionality(ip);
    
    if (previousFunctionality == GTPControl::UNDEFINED) 
    {
        _gatewayIPMap.insert(GatewayIPMapPair(ip, functionality));
    } 
    else 
    {
        if (functionality != previousFunctionality) 
        {
            CAPTOOL_MODULE_LOG_WARNING("Inconsistent functionality information for " <<  ip->getRawAddress() << ". Trying to set " << functionality << " (previous one was " << previousFunctionality << ").")			
        }
    }    
}

string
GTPControl::parseUserLocationIE(const u_int8_t * ie)
{
    int loc_length = ie[1] * 256 + ie[2];
    if (loc_length != 8 || ie[3] > 1)
    {
        CAPTOOL_MODULE_LOG_WARNING("unknown User Location IE, length: " << loc_length << ", type: " << (int)(ie[3]))
        return "";
    }
    else 
    {
        //u_int8_t type = ie[3];
        u_int8_t mcc[3];
        u_int8_t mnc[3];
        mcc[0] = ie[4] & 0x0f;
        mcc[1] = ie[4] >> 4;
        mcc[2] = ie[5] & 0x0f;
        mnc[0] = ie[6] & 0x0f;
        mnc[1] = ie[6] >> 4;
        mnc[2] = ie[5] >> 4;
        u_int16_t lac = htons(*(u_int16_t*)(ie+7));
        u_int16_t ci = htons(*(u_int16_t*)(ie+9));
        
        std::ostringstream s;
        s << (unsigned)(mcc[0]) << (unsigned)(mcc[1]) << (unsigned)(mcc[2]) << ":" << (unsigned)(mnc[0]) << (unsigned)(mnc[1]);
        if (mnc[2] < 15) 
        {
            s << (unsigned)(mnc[2]);
        }
        s << ":" << (unsigned)lac << ":" << (unsigned)ci;
        return s.str();
    }
}

void
GTPControl::getStatus(std::ostream *s, u_long, u_int)
{
    int sgsnIPs = 0;
    int ggsnIPs = 0;
    for (GatewayIPMap::iterator iter(_gatewayIPMap.begin()), end(_gatewayIPMap.end()); iter != end; ++iter)
    {
	    if ((NodeFunctionality)(iter->second) == GTPControl::SGSN) 
	    {
	        ++sgsnIPs;
	    }
	    if ((NodeFunctionality)(iter->second) == GTPControl::GGSN) 
	    {
	        ++ggsnIPs;
	    }
    }
    
    *s << "control tunnels: " << _pdpControlMap.size()
       << ", data tunnels: " << _pdpDataMap.size()
       << ", IPs: " << _ipMap.size()
       << ", SGSN IPs: " << sgsnIPs
       << ", GGSN IPs: " << ggsnIPs;
}

void
GTPControl::openNewFiles()
{
    ModuleManager::getInstance()->getFileManager()->openNewFile(_fileStream, _filePrefix, _filePostfix);
    _currentFileSize = 0;

    if (_pdpTimeout == 0) return;

    // Purge PDP contexts without user plane activity during a given timeout period
    std::set<PDPContext *> contextSet; // set for storing contexts to be deleted
    for (PDPContextMap::const_iterator it = _pdpControlMap.begin(); it != _pdpControlMap.end(); ++it)
    {
        if (it->second->getLastTimestamp().tv_sec < _lastTimestamp - _pdpTimeout)
        {
            contextSet.insert(it->second);
        }
    }
    for (std::set<PDPContext *>::iterator iter(contextSet.begin()), end(contextSet.end()); iter != end; ++iter)
    {
        deletePDPContext(*iter, true, 0);
    }
}

GTPControl::~GTPControl()
{
    // set for storing contexts to be deleted
    std::set<PDPContext *> contextSet;

    for (PDPContextMap::iterator iter(_pdpControlMap.begin()), end(_pdpControlMap.end()); iter != end; ++iter)
    {
        contextSet.insert((iter->second));
    }

    // delete contexts
    for (std::set<PDPContext *>::iterator iter(contextSet.begin()), end(contextSet.end()); iter != end; ++iter)
    {
        deletePDPContext(*iter, true, 0);
    }

    _pdpControlMap.clear();
    _pdpDataMap.clear();
}

IMSI::Ptr
GTPControl::parseIMSI (u_int8_t * const & ie)
const
{
    IMSI::Ptr imsi(new IMSI((uint8_t*) ie, _imsiKey, _anonymizeParanoid));
    return imsi;
}

IMEISV::Ptr
GTPControl::parseIMEISV (u_int8_t * const & ie)
const
{
    IMEISV::Ptr imei(new IMEISV((uint8_t*) ie, _anonymize));
    return imei;
}
