/*
 * LinuxCookedHeader.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __LINUX_COOKED_HEADER_H__
#define __LINUX_COOKED_HEADER_H__

#include <string>
#include <ostream>
#include <list>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

/**
 * Module for handling Linux cooked headers generated when reading from the "any" interface
 */
class LinuxCookedHeader : public captool::Module
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit LinuxCookedHeader(std::string name);

        /**
         * Destructor.
         */    
        ~LinuxCookedHeader();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        // inherited from Module
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);

        // inherited from Module
        int getDatalinkType();

    protected:
        
        // inherited from Module
        void initialize(libconfig::Config* config);
        
    private:
        
        /**
         * Structure for binding connections to protocols
         */
        struct Connection {
            /** network protocol number */
            u_int16_t  protocol;
            /** output module */
            Module    *module;
        };
        
        /** array of connection structures */
        struct Connection *_connections;
        
        /** length of the connections array */
        u_int              _connectionsLength;
	
        /** vlan used in length field for vlan tags */
        static const u_int16_t VLAN_TYPE;
};

#endif // __LINUX_COOKED_HEADER_H__
