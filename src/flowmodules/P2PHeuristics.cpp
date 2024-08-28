/*
 * P2PHeuristics.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "P2PHeuristics.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(P2PHeuristics)

P2PHeuristics::P2PHeuristics(string name)
    : Module(name),
    _ipMapSize(251)
{
}

P2PHeuristics::~P2PHeuristics()
{
    // TBD: write out statistics for the last period before terminating
    // This requires ensuring that FlowModule descructor be always called _BEFORE_ calling flow processing module descructors
}

void
P2PHeuristics::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);

    const string mygroup = "captool.modules." + _name;

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
    
    openNewFiles();
    
    ModuleManager::getInstance()->getFileManager()->registerFileGenerator(this);

    // Load other options (that can also be modified in runtime)
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));
}

void
P2PHeuristics::configure(const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("outputEnabled", _outputEnabled))
        CAPTOOL_MODULE_LOG_CONFIG("output " << (_outputEnabled ? "enabled" : "disabled") << ".")

    if (cfg.lookupValue("ipMapSize", _ipMapSize))
        CAPTOOL_MODULE_LOG_CONFIG("IP map size: " << _ipMapSize)
}


Module*
P2PHeuristics::process(const Flow* flow)
{
    assert(flow != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing flow.")
    
    // Only process flows with      1) known user ID 
    //                              2) at least one uplink packet
    //                              3) no classification tags
    //                              4) UDP or TCP transport
    ID::Ptr userID = flow->getUserID();
    if (userID.get() == 0 || flow->getUploadPackets() == 0 || !flow->getTags().isEmpty() || (flow->getID()->getProtocol() != IPPROTO_TCP && flow->getID()->getProtocol() != IPPROTO_UDP))
    {
        return _outDefault;
    }
    
    _periodEnd = flow->getLastTimestamp().tv_sec;
    if (_periodStart == 0)
        _periodStart = _periodEnd;
    
    P2PHeuristicsDescriptor::Ptr desc;
    HeuristicsMap::iterator it = _heuristicsMap.find(userID);
    if (it == _heuristicsMap.end())
    {
        desc = P2PHeuristicsDescriptor::Ptr(new P2PHeuristicsDescriptor(_ipMapSize));
        _heuristicsMap.insert(std::make_pair(userID, desc));
    }
    else
    {
        desc = it->second;
    }
    desc->update(flow);

    return _outDefault;
}

void
P2PHeuristics::openNewFiles()
{
    if (!_outputEnabled) 
    {
        return;
    }

    ModuleManager::getInstance()->getFileManager()->openNewFile(_fileStream, _filePrefix, _filePostfix);
    _currentFileSize = 0;
    
    // Write headers
    _fileStream << "#periodStart\tperiodEnd\tuserID\tunclassifiedBytesUL\tunclassifiedBytesDL\tunclassifiedFlows\tnumberOfPeersWithUnclassifiedTraffic\tpeerMap\n";
    
    writeStats();
}

void
P2PHeuristics::writeStats()
{
    // write out and delete all entries from the map, have a clean start for the new period
    for (HeuristicsMap::iterator it = _heuristicsMap.begin(); it != _heuristicsMap.end(); ++it)
    {
        _fileStream << _periodStart << "\t" << _periodEnd << "\t" << it->first << "\t" << *(it->second) << "\n";
        _currentFileSize += 15 + 1 + 8 + 1 + 8 + 1 + 3 + 1 + _ipMapSize + 1;
    }
    
    _fileStream.flush();
    
    _heuristicsMap.clear();
    _periodStart = _periodEnd = 0;
}

ostream& operator<<(ostream& o, const P2PHeuristicsDescriptor& desc)
{
    return o << desc._bytesUl << "\t" << desc._bytesDl << "\t" << desc._numberOfFlows << "\t" << desc._ipBitmap.count() << "\t" << desc._ipBitmap;
}

