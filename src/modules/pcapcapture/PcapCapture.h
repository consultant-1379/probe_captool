/*
 * PcapCapture.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PCAP_CAPTURE_H__
#define __PCAP_CAPTURE_H__

#include <string>
#include <ostream>

#include "libconfig.h++"

#include "captoolpacket/CaptoolPacket.h"
#include "modulemanager/activemodule/ActiveModule.h"

/**
 * Module for capturing @em pcap input from file or device.
 * It uses the @em libpcap library currently.
 * @par %Module configuration
 * @code
        capture:
        {
            type = "PcapCapture";

            connections = (                                 // 
                            ("default", "eth")              // *** IMPORTANT NOTE *** when using the KERNEL MODULE, packets should be forwarded directly to the IP module!
            );                                              //

            mode = "offline";                               // online/offline *** IMPORTANT NOTE *** when using the KERNEL MODULE, packets are read from a /proc file (need offline setting)
            input = "pipe";                                 // devicename/filename can be an interface name (e.g. eth0, br0), pcap file name, named pipe, proc file
            maxPackets = 0;                                 // stop capture after reading that many packets. 0 means infinity (default setting)
        };
 * @endcode
 */
class PcapCapture : public captool::ActiveModule
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit PcapCapture(std::string name);
        
        /**
         * Destructor.
         */    
        ~PcapCapture();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        // inherited from Module
        void getStatus(std::ostream *s, u_long runtime, u_int period);
    
    protected:
        
        void initialize(libconfig::Config *config);
        virtual void configure (const libconfig::Setting &);
        void interrupted();
        
    private:
        
        /** true if online mode; false otherwise */
        bool _onlineCapture;

        /** input name (either file or device) */
        std::string _inputName;
        
        /** descriptor of the pcap input */
        pcap_t* _pcapHandle;
        
        /** number of maximum packets to be read */
        u_int64_t _maxPackets;
        
        /** number of packets already read */
        u_int64_t _packets;
        
        /** header to be used with pcap packets */
        pcap_pkthdr _pcapHeader;
        
        /** traffic in bytes captured during last period */
        u_int64_t _periodTraffic;
        
        /** traffic in bytes captured during runtime */
        u_int64_t _totalTraffic;
};

#endif //__PCAP_CAPTURE_H__
