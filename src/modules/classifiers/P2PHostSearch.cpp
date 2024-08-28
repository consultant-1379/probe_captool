/*
 * P2PHostSearch.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "P2PHostSearch.h"

#include "classification/ClassificationMetadata.h"

using std::set;

using captool::CaptoolPacket;
using captool::Module;

DEFINE_CAPTOOL_MODULE(P2PHostSearch)

const unsigned P2PHostSearch::DEFAULT_HOST_TIMEOUT = 900;

P2PHostSearch::P2PHostSearch(string name)
    : Module(name),
      _sigId(0),
      _recheckPeriod(1000) // TBD: read from config
{
}

P2PHostSearch::~P2PHostSearch()
{
    for (map<unsigned, P2PHostList*>::const_iterator i = _p2pHostLists.begin(); i != _p2pHostLists.end(); ++i)
        delete i->second;
}

void
P2PHostSearch::initialize(libconfig::Config* config)
{
    assert(config != 0);

    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);

    // Read host timeout settings
    _timeout = DEFAULT_HOST_TIMEOUT;
    if (!config->lookupValue("captool.modules." + _name + ".timeout", _timeout))
    {
        CAPTOOL_MODULE_LOG_CONFIG("Host timeout not set, using default value (" << _timeout << "s).")
    }

    // Register the P2P host meta signatures
    registerSignatures("p2p-host");

}

void
P2PHostSearch::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("timeout", _timeout))
    {
        for (map<unsigned, P2PHostList*>::const_iterator i = _p2pHostLists.begin(); i != _p2pHostLists.end(); ++i)
            i->second->setTimeout(_timeout);
        CAPTOOL_MODULE_LOG_CONFIG("host entries time out after " << _timeout << "s.")
    }
}

void
P2PHostSearch::registerSignature(unsigned blockId, const Signature * signature)
{
    // Create P2P host list for the given block ID
    P2PHostList * list = new P2PHostList();
    list->setTimeout((time_t)_timeout);
    _p2pHostLists.insert(std::make_pair(blockId, list));
    
    // Read sigId and enforce the same sigId for all P2P blocks
    unsigned newSigId = signature->getId();
    if (_sigId == 0)
    {
        _sigId = newSigId;
    }
    else if (_sigId != newSigId)
    {
        CAPTOOL_MODULE_LOG_SEVERE("sigId for the p2p-host meta signature should be the same within each block.")
        exit(-1);
    }
}


Module*
P2PHostSearch::process(CaptoolPacket* captoolPacket)
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

    unsigned host1 = fid->getSourceIP()->getRawAddress();
    unsigned host2 = fid->getDestinationIP()->getRawAddress();

    // Go through each P2P host lists
    for (map<unsigned,P2PHostList*>::const_iterator it = _p2pHostLists.begin(); it != _p2pHostLists.end(); ++it)
    {
        // If both source end destination hosts are registered as users of the given P2P application, than a hint for this P2P application will be registered
        if (it->second->get(host1).get() && it->second->get(host2).get())
        {
            flow->setHint(it->first, _sigId);
        }
    }

    // Update or register new P2P host entries
    // Only rely on flows classified as final and having packets in both directions (in order to filter scanning activity)
    if (flow->isFinal() && flow->getUploadPackets() > 0 && flow->getDownloadPackets() > 0)
    {
        set<unsigned> finalBlocks = flow->getFinalBlockIds();

        // Go through each final blocks and if a P2P host list exists for the given block, 
        // than register or update entries for source and destination nodes
        for (set<unsigned>::const_iterator it = finalBlocks.begin(); it != finalBlocks.end(); ++it)
        {
            map<unsigned,P2PHostList*>::const_iterator hostListIt = _p2pHostLists.find(*it);
            if (hostListIt == _p2pHostLists.end())
            {
                // No P2P host list for the given block
                continue;
            }
            
            // P2P host list exists for this block, create or update entries
            const struct timeval timestamp = captoolPacket->getPcapHeader()->ts;
            // Remove timed out host entries
            hostListIt->second->cleanup(&timestamp);

            // Insert or update entry for source host
            boost::shared_ptr<HostTimestamp> entry1 = hostListIt->second->get(host1);
            if (entry1.get() == 0)
            {
                entry1 = boost::shared_ptr<HostTimestamp>(new HostTimestamp(timestamp));
                hostListIt->second->insert(host1, entry1);
            }
            else
            {
                entry1->_timestamp = timestamp;
                hostListIt->second->moveToEnd(host1);
            }
            // Insert or update entry for destination host
            boost::shared_ptr<HostTimestamp> entry2 = hostListIt->second->get(host2);
            if (entry2.get() == 0)
            {
                entry2 = boost::shared_ptr<HostTimestamp>(new HostTimestamp(timestamp));
                hostListIt->second->insert(host2, entry2);
            }
            else
            {
                entry2->_timestamp = timestamp;
                hostListIt->second->moveToEnd(host2);
            }
        }
    }

    return _outDefault;
}

void
P2PHostSearch::getStatus(std::ostream * s, u_long, u_int)
{
    *s << "Active P2P host entries: ";
    bool first = true;
    for (map<unsigned,P2PHostList*>::const_iterator it = _p2pHostLists.begin(); it != _p2pHostLists.end(); ++it)
    {
        if (first)
        {
            first = false;
        }
        else
        {
            *s << ",";
        }
        *s << "(";
        *s << ClassificationMetadata::getInstance().getBlockIdMapper().getName(it->first) << ":";
        *s << it->second->size();
        *s << ")";
    }
}

