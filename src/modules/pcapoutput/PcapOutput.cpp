/*
 * PcapOutput.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>
#include <sstream>

#include "modulemanager/ModuleManager.h"

#include "PcapOutput.h"

using std::string;
using std::istringstream;
using std::ostringstream;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(PcapOutput)

PcapOutput::PcapOutput(string name)
    : Module(name),
      _baseModule(0),
      _pcapHandle(0),
      _pcapDumper(0),
      _currentFileSize(0),
      _maxFileSize(2 << 26),
      _datalinkType(DLT_EN10MB),
      _snapLength(0),
      _flowPackets(0),
      _fixHeaders(true),
      _outputEnabled(true)
{
}

PcapOutput::~PcapOutput()
{
    // close dump file
    if (_pcapDumper != 0)
    {
        CAPTOOL_MODULE_LOG_INFO("closing dump file.")

        pcap_dump_close(_pcapDumper);
        _pcapDumper = 0;
    }
    
    // close handle
    if (_pcapHandle != 0)
    {
        pcap_close(_pcapHandle);
        _pcapHandle = 0;
    }
}

void
PcapOutput::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
            
    string mygroup = "captool.modules." + _name;
    
    // get file prefix
    if (!config->lookupValue(mygroup + ".filePrefix", _filePrefix))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filePrefix not set.")
        exit(-1);
    }

    // get file postfix
    if (!config->lookupValue(mygroup + ".filePostfix", _filePostfix))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filePrefix not set.")
        exit(-1);
    }

    string tmp;
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
        else
        {
            // set data link type by base module
            _datalinkType = _baseModule->getDatalinkType();
        }
    }    
    
    // open dead pcap handle
    _pcapHandle = pcap_open_dead(_datalinkType, 65535);
        
    if (_pcapHandle == 0)
    {
        CAPTOOL_MODULE_LOG_SEVERE("unable to open dead pcap.")
        exit(-1);
    }

    openNewFiles();
    
    // set max file size
    if (!config->lookupValue(mygroup + ".maxFileSize", _maxFileSize))
    {
        CAPTOOL_MODULE_LOG_CONFIG("maxFileSize not set, using default value (" << _maxFileSize << ").")
    }
    
    ModuleManager::getInstance()->getFileManager()->registerFileGenerator(this);
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));
}

void
PcapOutput::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;

    if (cfg.lookupValue("snapLength", _snapLength))
        CAPTOOL_MODULE_LOG_CONFIG("snaplength set to " << _snapLength << " bytes.")
        
    if (cfg.lookupValue("flowPackets", _flowPackets))
    {
        if (_flowPackets > 0)
            CAPTOOL_MODULE_LOG_CONFIG("dumping first " << _flowPackets << " packets of each flow.")
        else
            CAPTOOL_MODULE_LOG_CONFIG("dumping all packets of each flow.")
    }

    if (cfg.lookupValue("fixHeaders", _fixHeaders))
        CAPTOOL_MODULE_LOG_CONFIG((_fixHeaders ? "" : "not ") << "fixing invalid packet headers.")
    
    if (cfg.lookupValue("outputEnabled", _outputEnabled))
        CAPTOOL_MODULE_LOG_CONFIG("output " << (_outputEnabled ? "enabled" : "disabled") << ".")
}

Module*
PcapOutput::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    if (!_outputEnabled)
    {
        return _outDefault;
    }

    // dump packet if...
    if ( ( _flowPackets == 0) || (_flowPackets >= captoolPacket->getFlowNumber()) )
    {
        // request packet to generate byte array
        const pcap_pkthdr *header;
        const u_char *byteArray = captoolPacket->toByteArray(_baseModule, _snapLength, _fixHeaders, &header);

        // write to output
        if (byteArray != 0 && header != 0)
        {
            pcap_dump((u_char *)_pcapDumper, header, byteArray);
            
            _currentFileSize += header->caplen;
            
            if ( (_maxFileSize > 0) && (_currentFileSize >= _maxFileSize) )
            {
                ModuleManager::getInstance()->getFileManager()->fileSizeReached();
            }
            
        }
    }    
    
    // forward
    return _outDefault;
}

void
PcapOutput::openNewFiles()
{
    if (!_outputEnabled)
    {
        return;
    }

    ModuleManager::getInstance()->getFileManager()->openNewFile(&_pcapDumper, _filePrefix, _filePostfix, _pcapHandle);
    _currentFileSize = 0;
}
