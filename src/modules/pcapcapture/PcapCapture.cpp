/*
 * PcapCapture.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <string>
#include <sstream>

#include "PcapCapture.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(PcapCapture)

PcapCapture::PcapCapture(string name)
    : ActiveModule(name),
      _onlineCapture(false),
      _inputName(""),
      _pcapHandle(0),
      _maxPackets(0),
      _packets(0),
      _pcapHeader(),
      _periodTraffic(0),
      _totalTraffic(0)
{
}
    
PcapCapture::~PcapCapture()
{
    // close pcap if opened
    if (_pcapHandle != 0)
    {
        pcap_close(_pcapHandle);
        _pcapHandle = 0; 
    }
}

void
PcapCapture::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);

    const string mygroup = "captool.modules." + _name;
    
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));

    // get input
    string input;
    if (!config->lookupValue("captool.modules." + _name + ".input", input))
    {
        CAPTOOL_MODULE_LOG_SEVERE("input not set.")
        exit(-1);
    }

    // get mode
    string mode;
    if (!config->lookupValue("captool.modules." + _name + ".mode", mode))
    {
        CAPTOOL_MODULE_LOG_SEVERE("mode not set.")
        exit(-1);
    }

    // check mode
    if (mode == "online")
    {
        char pcapErrbuf[PCAP_ERRBUF_SIZE];
        _pcapHandle = pcap_open_live(const_cast<char *>(input.c_str()), 65535, 1, 0, pcapErrbuf);

        if (_pcapHandle == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("unable to open device \"" << input << "\" (" << pcapErrbuf << ").");
            exit(-1);
        }
        
        _onlineCapture = true;
    }
    else if (mode == "offline")
    {
        char pcapErrbuf[PCAP_ERRBUF_SIZE];
        _pcapHandle = pcap_open_offline(const_cast<char *>(input.c_str()), pcapErrbuf);

        if (_pcapHandle == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("unable to open file \"" << input << "\" (" << pcapErrbuf << ").");
            exit(-1);
        }
        
        _onlineCapture = false;
    }
    else
    {
        CAPTOOL_MODULE_LOG_SEVERE("invalid mode set.");
        exit(-1);
    }
    
    assert(_pcapHandle != 0);
}

void
PcapCapture::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("maxPackets", _maxPackets))
        CAPTOOL_MODULE_LOG_CONFIG("capturing at most " << _maxPackets << " packets.")
}

Module *
PcapCapture::process(CaptoolPacket *captoolPacket)
{
    assert(captoolPacket != 0);

    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    _packets++;
    // stop if packet number limit is reached
    if (_maxPackets && _packets >= _maxPackets)  // FIXME add unlikely
    {
        finished();
    }

    int ret = pcap_next_ex(_pcapHandle, captoolPacket->getPcapHeaderPtr(), captoolPacket->getPcapPacketPtr());
    
    if (ret == 0)
    {
        CAPTOOL_MODULE_LOG_WARNING("capture timed out.");
        //finished(); // Also happened a few times during normal runtime...
        return 0;
    }
    
    if (ret == -1)
    {
        CAPTOOL_MODULE_LOG_SEVERE("error reading packet.");
        finished();
        return 0;
    }
    
    if (ret == -2)
    {
        CAPTOOL_MODULE_LOG_WARNING("input end.");
        finished();
        return 0;
    }
    
    captoolPacket->initialize(_packets);
    const struct pcap_pkthdr *header = captoolPacket->getPcapHeader();
    
    CAPTOOL_MODULE_LOG_FINEST("received packet no. " << _packets
                         << " at " << captoolPacket->getPcapHeader()->ts.tv_sec
                         << "." << captoolPacket->getPcapHeader()->ts.tv_usec
                         << ", caplen is " << captoolPacket->getPcapHeader()->caplen )

    // check for out of order packet
    if (_currentTime.tv_sec > header->ts.tv_sec || (_currentTime.tv_sec == header->ts.tv_sec && _currentTime.tv_usec > header->ts.tv_usec) )
    {
        CAPTOOL_MODULE_LOG_WARNING("out of order packet. (no. " << _packets << ")")
    }
    else
    {
        _currentTime = header->ts;
    }
    
    _periodTraffic += header->len;
    
    // forward
    return _outDefault;
}

void
PcapCapture::interrupted()
{
    pcap_breakloop(_pcapHandle);
}

void
PcapCapture::getStatus(std::ostream *s, u_long runtime, u_int period)
{
    assert(s != 0);
    
    *s << "packets: " << _packets;

    if (_onlineCapture)
    {
        pcap_stat stat;
        pcap_stats(_pcapHandle, &stat);
        
        *s << "; stat: recv: " << stat.ps_recv << ", drop: " << stat.ps_drop
            << " (" << (100.0 * stat.ps_drop)/stat.ps_recv << "%)";
    }
    
    if (runtime != 0)
    {
        _periodTraffic >>= 17; // byte->mbit

        if (_totalTraffic == 0)
        {
            _totalTraffic = _periodTraffic;
        }

        *s << "; traffic: period: " << ((double)_periodTraffic) / period << "Mbps";
        
        // weighted-moving average with alpha=.25
        _periodTraffic >>= 2;
        _totalTraffic -= (_totalTraffic >> 2);
        _totalTraffic += _periodTraffic;
        
        *s << ", total: " << ((double)_totalTraffic) / period << "Mbps";
    }
    
    _periodTraffic = 0;
}
