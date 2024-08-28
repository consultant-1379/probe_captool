/*
 * Summarizer.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "Summarizer.h"
#include <utility>
#include <sstream>
#include "classification/ClassificationMetadata.h"
#include "classification/TagContainer.h"

namespace captool {

DEFINE_CAPTOOL_MODULE(Summarizer)

Summarizer::Summarizer(std::string name) : Module(name), start(0), end(0), facetcount(0) {}
    
Summarizer::~Summarizer()
{
    flush();
}

Module*
Summarizer::process(CaptoolPacket* pkt)
{
    Flow::Ptr flow = pkt->getFlow();
    if (! flow || ! flow->getID()->isSet())
    {
        CAPTOOL_MODULE_LOG_WARNING("flow undefined for packet no. " << pkt->getPacketNumber() << "; omitting");
        return _outDefault;
    }
    
    end = pkt->getPcapHeader()->ts.tv_sec;
    if (start == 0) start = end;
    
    IPAddress::Ptr ip = flow->getID()->getSourceIP();
    const UserID userid(pkt->getUserID(), ip, pkt->getEquipmentID());
    const UserAppID userappid(userid, flow->getTags());
    
    UserAppMap::iterator userappiter = userapps.find(userappid);
    if (userappiter == userapps.end())
        userappiter = userapps.insert(std::make_pair(userappid, UserAppStats())).first;
    UserAppStats & userstats = userappiter->second;
    
    bool uplink = pkt->getDirection() == CaptoolPacket::UPLINK;
    
    unsigned pktbytes = pkt->getSegmentsTotalLength(baseModule);
    
    FlowMap::iterator flowiter = flows.find(flow);
    if (flowiter == flows.end())
        flowiter = flows.insert(std::make_pair(flow,
                                                FlowStats(flow->getUploadBytes() - (uplink ? pktbytes : 0),
                                                          flow->getDownloadBytes() - (uplink ? 0 : pktbytes),
                                                          userappid.tags
                                                ))).first;
    
    if (flow->getLastHintedPacketNumber() == pkt->getFlowNumber())
    {
        FlowStats & flowstats = flowiter->second;
        const size_t flowtags = userappid.tags;
        const size_t oldtags = flowstats.tags;
        
        if (flowtags != oldtags)
        {
            // flow got reclassified;  move totals from old class (possibly n/a) to the appropriate class
            
            UserAppID previd(userid, oldtags);
            UserAppMap::iterator previter = userapps.find(previd);
            
            if (previter == userapps.end())
            {
                CAPTOOL_MODULE_LOG_SEVERE("packet " << pkt->getPacketNumber() << " in flow at " << std::hex << (void *) flow.get() << std::dec << " reclassified from tags " << oldtags << " to " << flowtags << " but previous stats not in map");
            }
            else
            {
                UserAppStats & prevstats = previter->second;
                
                unsigned long long totalup = flow->getUploadBytes() - flowstats.upoffset - (uplink ? pktbytes : 0);
                unsigned long long totaldown = flow->getDownloadBytes() - flowstats.downoffset - (uplink ? 0 : pktbytes);
                
                if (totalup > 0)
                {
                    if (prevstats.up < totalup) {
                        CAPTOOL_MODULE_LOG_SEVERE("packet " << pkt->getPacketNumber() << " in flow at " << std::hex << (void*) flow.get() << std::dec << " prevstats.up < totalup;  setting to 0");
                        prevstats.up = 0;
                    }
                    else
                        prevstats.up -= totalup;
                    
                    userstats.up += totalup;
                }
                
                if (totaldown > 0)
                {
                    if (prevstats.down < totaldown) {
                        CAPTOOL_MODULE_LOG_SEVERE("packet " << pkt->getPacketNumber() << " in flow at " << std::hex << (void*) flow.get() << std::dec << " prevstats.down < totaldown;  setting to 0");
                        prevstats.down = 0;
                    }
                    else
                        prevstats.down -= totaldown;
                    
                    userstats.down += totaldown;
                }
                
                if (prevstats.up == 0 && prevstats.down == 0)
                    userapps.erase(previter);
            }
            
            flowstats.tags = flowtags;
        }
    }
    
    if (uplink)
    {
        userstats.up += pktbytes;
    }
    else
    {
        userstats.down += pktbytes;
    }
    
    return _outDefault; 
}

void
Summarizer::flush()
{
    out << "# start end user equipment ip up down " << facetnames << std::endl;
    
    for (UserAppMap::iterator i = userapps.begin(); i != userapps.end(); ++i)
    {
        const UserAppID & id = (*i).first;
        const UserAppStats & st = (*i).second;
        
        out << start << "\t" << end << "\t" << id.user.userid << "\t" << id.user.equipment
            << "\t" << id.user.ip << "\t" << st.up << "\t" << st.down << "\t" << id.tagstring << std::endl;
    }
    
    out.flush();
    
    flows.clear();
    userapps.clear();
}

void
Summarizer::openNewFiles()
{
    if (start) flush();
    
    start = end = 0;
    
    if (facetnames == "")
    {
        facetcount = ClassificationMetadata::getInstance().getFacetIdMapper().size();
        
        std::ostringstream oss;
        
        for (size_t i = 1; i <= facetcount; ++i)
        {
            if (i > 1) oss << " ";
            
            oss << ClassificationMetadata::getInstance().getFacetIdMapper().getName(i);
        }
        
        facetnames = oss.str();
    }
    
    ModuleManager::getInstance()->getFileManager()->openNewFile(out, filePrefix, filePostfix);
}

void
Summarizer::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")
    
    Module::initialize(config);

    std::string tmp;

    if (!config->lookupValue("captool.modules." + _name + ".baseModule", tmp))
    {
        CAPTOOL_MODULE_LOG_CONFIG("baseModule not set.")
    }
    else
    {
        baseModule = ModuleManager::getInstance()->getModule(tmp);
            
        if (baseModule == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("baseModule not found.")
            exit(-1);
        }
    }    
    
    if (!config->lookupValue("captool.modules." + _name + ".filePrefix", filePrefix))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filePrefix not set.")
        exit(-1);
    }

    if (!config->lookupValue("captool.modules." + _name + ".filePostfix", filePostfix))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filePrefix not set.")
        exit(-1);
    }
    
    openNewFiles();
    
    ModuleManager::getInstance()->getFileManager()->registerFileGenerator(this);
}

Summarizer::UserID::UserID(ID::Ptr const& user, const IPAddress::Ptr & ipaddr, ID::Ptr const& equip)
  : userid(user),
    equipment(equip),
    ip(0),
    hash(0)
{
    if (ipaddr)
    {
        ip = ipaddr->getRawAddress();
        hash = ipaddr->hashValue();
    }
}

bool 
Summarizer::UserID::operator== (const UserID& other) const
{
    if (userid && other.userid)
        if (userid != other.userid)
            return false;
    return ip == other.ip;
}

bool 
Summarizer::UserAppID::operator== (const UserAppID& other) const
{
    return user == other.user && tags == other.tags;
}

Summarizer::UserAppID::UserAppID(const UserID & uid, const TagContainer & tc)
  : user(uid)
{
    tags = tc.hashCode();
    tagstring = tc.str();
}

std::size_t 
Summarizer::UserAppIDHasher::operator() (UserAppID const& id) const
{
    return id.user.hash ^ id.tags;
}

} // captool::
