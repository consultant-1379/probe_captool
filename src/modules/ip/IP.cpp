/*
 * IP.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <iostream>
#include <arpa/inet.h>

#include <pcap.h>
#include <list>
#include <map>

#include "modulemanager/ModuleManager.h"
#include "ip/IPAddress.h"

#include "IP.h"
#include "IPFragments.h"


using std::string;

using std::map;
using std::pair;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(IP)

IP::IP(string name)
    : Module(name),
      _idFlows(false),
      _defrag(true),
      _filterFragments(false),
      _trunc(false),
      _fragments(120),
      _fragmentsPool(),
      _nextCleanupAt(FRAGMENT_CLEANUP_INTERVAL),
      maxfragmented(10000),
      _connections(0),
      _connectionsLength(0),
      _ipv6Module(0),
      _totalTraffic(0)
{
    // Clear traffic statistics
    for (unsigned i=0; i<256; i++)
    {
        _trafficStatistics[i] = 0;
    }
}

IP::~IP()
{
    // free all IPFragmentses and IPFragmentIDs
    for(FragmentsMap::iterator iter(_fragments.begin()), end(_fragments.end()); iter != end;)
    {
        IPFragmentsID *fragID = (IPFragmentsID *)iter->first;
        IPFragments *frag = (IPFragments *)iter->second;

        _fragments.erase(iter++);
        
        delete (fragID);
        _fragmentsPool.freeObject(frag);
        
    }
    
    delete[] (_connections);
}

void
IP::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")
            
    Module::initialize(config);
    
    const std::string mygroup = "captool.modules." + _name;
    /* configure connections */

    libconfig::Setting& connectionSettings = config->lookup(mygroup + ".connections");
    
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
        
        int protocol = connection[0];
        
        if (protocol < 0 || protocol > 255)
        {
            CAPTOOL_MODULE_LOG_SEVERE("protocol number must be between 0 and 255.")
            exit(-1);
        }
        
        string moduleName = connection[1];
        Module *module = ModuleManager::getInstance()->getModule(moduleName);
        if (module == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
            exit(-1);
        }

        _connections[_connectionsLength].protocol = protocol;
        _connections[_connectionsLength].module = module;
        ++_connectionsLength;
    }
    
    // get ipv6 handler module
    // No real IPv6 support yet. However, this allows passing IPv6 packets to a PcapOuptut module which dumps these packets to separate pcap files
    string tmp;
    if (!config->lookupValue(mygroup + ".ipv6Module", tmp))
    {
        if (_idFlows)
        {
            // This warning should not be issued for the GTP encapsulating IP module
            CAPTOOL_MODULE_LOG_WARNING("ipv6Module not set. IPv6 packets will be dropped.")
        }
    }
    else
    {
        _ipv6Module = ModuleManager::getInstance()->getModule(tmp);
        if (_ipv6Module == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("ipv6Module not found. IPv6 packets will be dropped.")
        }
    }
    
    config->lookupValue("captool.securityManager.anonymize", _trunc);
    
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));
}

void
IP::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("idFlows", _idFlows))
        CAPTOOL_MODULE_LOG_CONFIG((_idFlows ? "" : "not ") << "filling in flow ID elements.")

    if (cfg.lookupValue("defrag", _defrag))
        CAPTOOL_MODULE_LOG_CONFIG((_defrag ? "" : "not ") << "defragmenting IP packets.")

    if (! _defrag && cfg.lookupValue("filterFragments", _filterFragments))
        CAPTOOL_MODULE_LOG_CONFIG((_filterFragments ? "not " : "") << "keeping non-first fragments of IP packets.")
}

Module*
IP::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    size_t payloadLength;
    struct iphdr* ip = (struct iphdr *)captoolPacket->getPayload(&payloadLength);

    assert(ip != 0);
    
    if (ip->version == 4)
    {
        return processIPv4(captoolPacket);
    }
    else if(ip->version == 6)
    {
        if (_ipv6Module == 0)
        {
            return 0;
        }
    
        // No real IPv6 support yet. 
        // However, this allows passing IPv6 packets to a PcapOutput module which dumps these packets to separate pcap files
        captoolPacket->saveSegment(this, payloadLength);
        return _ipv6Module;
    }
    else
    {
        CAPTOOL_MODULE_LOG_INFO("packet is not IPv4/IPv6. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }

}

Module*
IP::processIPv4(captool::CaptoolPacket *captoolPacket)
{
    assert(captoolPacket != 0);
    
    size_t payloadLength;
    struct iphdr* ip = (struct iphdr *)captoolPacket->getPayload(&payloadLength);

    assert(ip != 0);

    u_int8_t headLength  = ip->ihl * 4; // 4-byte
    
    // make sure the length to be saved can be saved
    if (payloadLength < headLength)
    {
        CAPTOOL_MODULE_LOG_INFO("payload is too short for an IP header. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }
    
    // make sure length is at least min. IP header length long
    if (headLength < 20)
    {
        CAPTOOL_MODULE_LOG_WARNING("ihl must be at least 5. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }
    
    u_int16_t length = ntohs(ip->tot_len);
    
    // make sure total length of packet is at least head length long
    if (length < headLength)
    {
        CAPTOOL_MODULE_LOG_WARNING("invalid length field. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }

    // drop bogus packets with 0 src IP address
    if (ip->saddr == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("IP src address is 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;    
    }
    
    // drop bogus packets with 0 dst IP address
    if (ip->daddr == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("IP dst address is 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;    
    }
    
    // save current segment
    captoolPacket->saveSegment(this, headLength);
    
    // drop packet if transport protocol is set to 0 ==> "IPv6 hop-by-hop option"
    if (ip->protocol == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("protocol set to 0. Dropping packet. (no. " << captoolPacket->getPacketNumber() << ")")
        return 0;
    }
    
    u_int16_t frags       = ntohs(ip->frag_off);
    // find fragment offset
    u_int16_t fragOff     = (frags & IP_OFFMASK) * 8; // 8-byte
    // check if there are more fragments
    bool      moreFrags   = frags & IP_MF;
    
    // is this a fragment ?
    if ( moreFrags || (fragOff != 0) )
    {
        if (_defrag)
        {
            if (captoolPacket->getPacketNumber() > _nextCleanupAt)
            {
                fragmentsCleanup( &(captoolPacket->getPcapHeader()->ts) );
                _nextCleanupAt = captoolPacket->getPacketNumber() + FRAGMENT_CLEANUP_INTERVAL;
            }

            CAPTOOL_MODULE_LOG_FINER("packet is a fragment. (no. " << captoolPacket->getPacketNumber() << ")")

            // create IPFragmentID
            IPFragmentsID* id = new IPFragmentsID(ip->saddr, ip->daddr, ip->id, ip->protocol);

            // check if Fragment already exists
            IPFragments   *frags = 0;
            IPFragmentsID *fragID = 0;

            FragmentsMap::const_iterator iter = _fragments.find(id);
            if (iter == _fragments.end())
            {
                if (_fragmentsPool.size() <= maxfragmented)
                {
                    CAPTOOL_MODULE_LOG_FINER("new fragmented ip")

                    // create new IPFragments
                    IPFragments* newFrags = _fragmentsPool.getObject();

                    assert(newFrags != 0);

                    newFrags->initialize(&(captoolPacket->getPcapHeader()->ts));

                    _fragments.insert(FragmentsMapPair(id, newFrags));
                    frags = newFrags;
                    fragID = id;
                }
                else
                {
                    CAPTOOL_MODULE_LOG_FINER("maximum fragmented IP packet count reached (" << _fragmentsPool.size() << ");  dropping this fragment");
                    delete id;
                    return 0;
                }
            }
            else
            {
                CAPTOOL_MODULE_LOG_FINER("existing fragmented ip")

                delete (id);

                fragID = (IPFragmentsID *)iter->first;
                frags = (IPFragments *)iter->second;

            }

            assert(frags != 0);

            if (length > headLength)
            {
                // register current fragment
                frags->addFragment(captoolPacket->getPayload(0), fragOff, length - headLength, moreFrags);
            }
            
            // is package reassemblable
            if (frags->isCompleted())
            {
                // get assembled payload
                u_int lght;
                const u_char *payload = frags->getAssembledPayload(&lght);

                CAPTOOL_MODULE_LOG_FINE("last fragment received. Assembling defragmented packets.")

                // update packets timestamp to first one and update payload to assembled one        
                bool changed = captoolPacket->changePayload(payload, lght);
                
                // remove fragment from map
                _fragments.erase(fragID);

                // free fragments
                _fragmentsPool.freeObject(frags);
                delete (fragID);
                
                if (! changed) {
                    CAPTOOL_MODULE_LOG_WARNING("cannot asssemble IP fragments due low memory;  dropping packet no. " << captoolPacket->getPacketNumber());
                    return 0;
                }
            } else {
                return 0;
            }
            
        }
        else
        {
            // do not defrag and drop not-first fragments
            if (_filterFragments && fragOff != 0)
            {
                return 0;
            }
            
        }
    }
    
    // Not fragmented packets, and defragmented packets
    
    // id flows
    if (_idFlows)
    {
        captoolPacket->getFlowID().setIP(IPAddress::Ptr(new IPAddress(ip->saddr, _trunc)), IPAddress::Ptr(new IPAddress(ip->daddr)), ip->protocol);
    }
    
    // update per transport protocol traffic statistics
    _totalTraffic += length;
    _trafficStatistics[ip->protocol] += length;

    // forward
    for (u_int i=0; i<_connectionsLength; ++i)
    {
        if (_connections[i].protocol == ip->protocol)
        {
            return _connections[i].module;
        }
    }
    
    return _outDefault;
}

void
IP::describe(const CaptoolPacket *captoolPacket, std::ostream *s)
{
    assert(captoolPacket != 0);
    assert(s != 0);

    CAPTOOL_MODULE_LOG_FINEST("describing packet.")
    
    struct iphdr *ip = (struct iphdr *)captoolPacket->getSegment(this, 0);

    assert(ip != 0);
    
    *s << "src: ";
    IPAddress::toString(ip->saddr, s);
    *s << ", dst: ";
    IPAddress::toString(ip->daddr, s);
    *s << ", hl: " << (ip->ihl * 4)
      << ", id: " << ntohs(ip->id)
      << ", length: " << ntohs(ip->tot_len)
      << ", more: " << (ntohs(ip->frag_off) & IP_MF)
      << ", off: " << ((ntohs(ip->frag_off) & IP_OFFMASK) * 8);
}

void
IP::fixHeader(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINE("fixing header.")
    
    struct iphdr *ip = (struct iphdr *)captoolPacket->getSegment(this, 0);

    assert(ip != 0);
    
    u_int totalLength = captoolPacket->getSegmentsTotalLength(this);

    assert(totalLength > 0);
    
    // unset offset and more fragments
    ip->frag_off = 0;
    // update packet length
    ip->tot_len = htons(totalLength);
    // recalculate checksum
    ip->check = 0;
    ip->check = checksum((u_int16_t *)ip, totalLength);
}

u_int16_t
IP::checksum(u_int16_t *ip, u_int length)
{
    assert(ip != 0);
    assert(length > 0);
    
    register u_int32_t sum = 0;

    while( length > 1 )
    {
       /*  This is the inner loop */
           sum += *ip++;
           
           if (sum & 0x80000000)
           {
               sum = (sum & 0xffff) + (sum >> 16);
           }
           length -= 2;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
   
    return ~sum;
}    

void
IP::fragmentsCleanup(const struct timeval *time)
{
    for(FragmentsMap::iterator iter(_fragments.begin()), end(_fragments.end()); iter != end;)
    {
        IPFragments *frags = (IPFragments *)iter->second;

        if (time->tv_sec > frags->getTimestamp()->tv_sec + FRAGMENT_TIMEOUT)
        {
            IPFragmentsID *fragID = (IPFragmentsID *)iter->first;
            _fragments.erase(iter++);
            _fragmentsPool.freeObject(frags);
            delete (fragID);
            CAPTOOL_MODULE_LOG_FINEST("fragment freed up.")
        }
        else
        {
            ++iter;
        }
    }
}


void
IP::getStatus(std::ostream *s, u_long, u_int)
{
    // Defragmentation info
    *s << "active fragments: " << _fragments.size() << ". ";

    // Compile an ordered list of per transport protocol stats
    std::multimap<u_int64_t,u_int8_t> statistics;
    for (unsigned i=0; i<256; i++)
    {
        if (_trafficStatistics[i] > 0)
        {
            statistics.insert(std::make_pair(_trafficStatistics[i], (u_int8_t)i));
        }
    }
    *s << "Traffic mix: ";
    bool first = true;
    for (std::multimap<u_int64_t,u_int8_t>::const_reverse_iterator rit = statistics.rbegin(); rit != statistics.rend(); ++rit)
    {
        if (first)
        {
            first = false;
        }
        else
        {
            *s << ", ";
        }
        *s << FlowID::ipProtocolToString(rit->second) << "=" << (rit->first * 100.0 / _totalTraffic) << "%";
    }

    // Clear statistics for the next period
    _totalTraffic = 0;
    for (unsigned i=0; i<256; i++)
    {
        _trafficStatistics[i] = 0;
    }
}

int
IP::getDatalinkType()
{
    return DLT_RAW;
}            

