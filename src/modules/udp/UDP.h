/*
 * UDP.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __UDP_H__
#define __UDP_H__

#include <string>
#include <ostream>
#include <list>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#define UDP_HDR_LEN              8

/**
 * Module for handling UDP headers.
 * @par %Module configuration
 * @code
 *        udp:
 *        {
 *            type = "UDP";
 *
 *            connections = (                                 // based on udp ports
 *                            (2123, "gtpc"),                 // GTP-C traffic
 *                            (2152, "gtpu")                  // GTP-U traffic
 *            );
 *
 *            idFlows = false;                                // update port number fields of flowID in packet or not
 *        };
 * @endcode
 */
class UDP : public captool::Module
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit UDP(std::string name);
        
        /**
         * Destructor.
         */    
        ~UDP();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        // inherited from Module
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);
        
        // inherited from Module
        void fixHeader(captool::CaptoolPacket* captoolPacket);
    
    protected:
        
        void initialize(libconfig::Config* config);
        virtual void configure (const libconfig::Setting &);
        
    private:
        
        /** true if it should fill the packet's flowID */
        bool _idFlows;
    
        /**
         * Structure for binding connections to ports.
         */
        struct Connection {
            /** port number */
            u_int16_t  port;
            /** output module */
            Module    *module;
        };
        
        /** array of connection structures */
        struct Connection *_connections;
        
        /** length of the connections array */
        u_int              _connectionsLength;
};

#endif // __UDP_H__
