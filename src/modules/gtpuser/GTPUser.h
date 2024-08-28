/*
 * GTPUser.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __GTP_USER_H__
#define __GTP_USER_H__

#include <string>
#include <ostream>

#include "libconfig.h++"

#include "modulemanager/Module.h"

#include "modules/ip/IP.h"
#include "modules/gtpcontrol/GTPControl.h"
#include "captoolpacket/CaptoolPacket.h"

#include "modules/gtpcontrol/gtp.h"

/**
 * Module for handling GTP-U messages
 */
class GTPUser : public captool::Module
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit GTPUser(std::string name);

        /**
         * Destructor.
         */    
        ~GTPUser();

        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);

        // inherited from Module
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);

    protected:
        
        // inherited from Module
        void initialize(libconfig::Config* config);

    private:
        
        /**
         * Parses the next extension header of the gtp header.
         *
         * @param begin pointer to the beginning of this extension header
         * @param length pointer where the length of this extension header is to be returned
         *
         * @return true if there is another extension header following this one
         */
        bool parseNextExt(const u_int8_t* begin, u_int8_t* length);

        /** the IP module that should be requested for the GSN IP Address of the current packet */
        IP *_gsnIPModule;
        
        /** the GTPControl module that should be requested for the PDPContext of a packet */
        GTPControl *_gtpControlModule;

        /**
         * Structure for binding connections to content types
         */
        struct Connection {
            /** content type */
            u_int8_t  type;
            /** output module */
            Module    *module;
        };

        /** array of connection structures */
        struct Connection *_connections;
        
        /** length of the connections array */
        u_int              _connectionsLength;
};

inline bool
GTPUser::parseNextExt(const u_int8_t* begin, u_int8_t* length)
{
    assert(begin != 0);
    assert(length > 0);

    *length = begin[0];
    return (begin[*length - 1] != 0);
}

#endif // __GTP_USER_H__
