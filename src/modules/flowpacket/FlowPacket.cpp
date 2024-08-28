  /*
 * FlowPacket.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <iostream>
#include <cassert>
#include <arpa/inet.h>
#include <cstring>
#include <algorithm> // min()
#include "modulemanager/ModuleManager.h"
#include "FlowPacket.h"
#include "classification/ClassificationMetadata.h"
#include "classification/FacetClassified.h"
#include "flow/Flow.h"
#include "FlowPacketFileStruct.h"

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(FlowPacket)

const size_t FlowPacketFileStruct::ID_LENGTH;

const std::string FlowPacket::FILE_HEADER ("Captool packet log");
const unsigned FlowPacket::FILE_VERSION = 1;

FlowPacket::FlowPacket(std::string name)
    : Module(name),
      _baseModule(0),
      _currentFileSize(0),
      _maxFileSize(2 << 26),
      _outputEnabled(true),
      _anonymize(false)
{
}

FlowPacket::~FlowPacket()
{
    // close stream
    if (_fileStream.is_open())
    {
        _fileStream.flush();
        _fileStream.close();
    }
 
}

void
FlowPacket::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")
            
    Module::initialize(config);

    std::string mygroup = "captool.modules." + _name;
    std::string tmp;

    // get base module
    if (!config->lookupValue(mygroup + ".baseModule", tmp))
    {
        CAPTOOL_MODULE_LOG_CONFIG("baseModule not set.")
    }
    else
    {
        _baseModule = ModuleManager::getInstance()->getModule(tmp);
            
        if (_baseModule == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("baseModule not found. Discarding.")
        }
    }    
    
    // get file prefix
    if (!config->lookupValue(mygroup + ".filePrefix", _filePrefix))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filePrefix not set.")
        exit(-1);
    }

    // get file postfix
    if (!config->lookupValue(mygroup + ".filePostfix", _filePostfix))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filePostfix not set.")
        exit(-1);
    }

    openNewFiles();

    // set max file size
    if (!config->lookupValue(mygroup + ".maxFileSize", _maxFileSize))
    {
        CAPTOOL_MODULE_LOG_CONFIG("maxFileSize not set, using default value (" << _maxFileSize << ").")
    }
    
    if (config->lookupValue("captool.securityManager.anonymize", _anonymize))
    {
        CAPTOOL_MODULE_LOG_WARNING("subscriber IPs will" << (_anonymize ? "" : " not") << " be anonymized.")
    }

    ModuleManager::getInstance()->getFileManager()->registerFileGenerator(this);
    
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));
}

void
FlowPacket::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("outputEnabled", _outputEnabled))
        CAPTOOL_MODULE_LOG_CONFIG("output " << (_outputEnabled ? "enabled" : "disabled") << ".");
}

Module*
FlowPacket::process(CaptoolPacket* captoolPacket)
{
    if (!_outputEnabled)
    {
        return _outDefault;
    }

    assert(captoolPacket != 0);

    CAPTOOL_MODULE_LOG_FINEST("processing packet.")
    
    static const uint8_t facets = ClassificationMetadata::getInstance().getFacetIdMapper().size();
    
    FlowID & fid = captoolPacket->getFlowID();
    
    _header.secs = htonl(captoolPacket->getPcapHeader()->ts.tv_sec);
    _header.usecs = htonl(captoolPacket->getPcapHeader()->ts.tv_usec);
    _header.srcIP = htonl(fid.getSourceIP()->getRawAddress());
    _header.dstIP = htonl(fid.getDestinationIP()->getRawAddress());
    _header.length = htonl(captoolPacket->getSegmentsTotalLength(_baseModule));
    _header.srcPort = htons(fid.getSourcePort());
    _header.dstPort = htons(fid.getDestinationPort());
    _header.protocol = fid.getProtocol();
    const CaptoolPacket::Direction dir = captoolPacket->getDirection();
    _header.direction = dir == CaptoolPacket::UPLINK ? 'u' : (dir == CaptoolPacket::DOWNLINK ? 'd' : ' ');
    
    if (_anonymize)
    {
        if (dir == CaptoolPacket::UPLINK || dir == CaptoolPacket::UNDEFINED_DIRECTION)
            _header.srcIP &= 0xffff0000;
        if (dir == CaptoolPacket::DOWNLINK || dir == CaptoolPacket::UNDEFINED_DIRECTION)
            _header.dstIP &= 0xffff0000;
    }
    
    fillID(_header.user, captoolPacket->getUserID());
    fillID(_header.equipment, captoolPacket->getEquipmentID());
    
    Flow::Ptr & flow = captoolPacket->getFlow();
    _header.facets = (flow) ? facets : 0;
    
    std::size_t len = sizeof(struct FlowPacketFileStruct);
    _fileStream.write((const char *) &_header, len);
    if (flow)
        for (unsigned i = 1; i <= facets; ++i)
        {
          uint16_t val = htons(flow->getTag(i));
          _fileStream.write((const char *) &val, sizeof(uint16_t));
          len += sizeof(uint16_t);
        }
    
    _currentFileSize += len;

    if ( (_maxFileSize > 0) && (_currentFileSize >= _maxFileSize) )
    {
        ModuleManager::getInstance()->getFileManager()->fileSizeReached();
    }
        
    return _outDefault;
}

void
FlowPacket::openNewFiles()
{
    if (!_outputEnabled)
        return;
    ModuleManager::getInstance()->getFileManager()->openNewFile(_fileStream, _filePrefix, _filePostfix);
    _fileStream << FILE_HEADER << " " << FILE_VERSION;
    _fileStream.put('\0');
    _currentFileSize = 0;
}

void
FlowPacket::fillID(uint8_t * field, ID::Ptr const & id)
{
    if (id)
    {
        std::size_t len = std::min(id->size(), FlowPacketFileStruct::ID_LENGTH);
        std::memcpy((void*) field, (void*) id->raw(), len);
        std::memset(field + len, 0, FlowPacketFileStruct::ID_LENGTH - len);
    } else
        std::memset(field, 0, FlowPacketFileStruct::ID_LENGTH);
}
