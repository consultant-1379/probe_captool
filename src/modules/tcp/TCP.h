/*
 * TCP.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __TCP_H__
#define __TCP_H__

#include <string>
#include <ostream>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#define TCP_HEADER_CORE_LENGTH 20

/**
 * Module for handling TCP headers
 * @par %Module configuration
 * @code
 * tcp2:
 * {
 *   type = "TCP";
 * 
 *   connections = (
 *                  ("default", "flow")
 *                 );
 * 
 *   idFlows = true;  // fill in flowID in packet?
 * };
 * @endcode
 */
class TCP : public captool::Module
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit TCP(std::string name);
        
        /**
         * Destructor.
         */    
        ~TCP();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        // inherited from Module
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);
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

#endif // __TCP_H__
