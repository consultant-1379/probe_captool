/*
 * ETH.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __ETH_H__
#define __ETH_H__

#include <string>
#include <ostream>
#include <list>
#include <tr1/unordered_map>
#include <libconfig.h++>

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"
#include "userid/MACAddress.h"

/**
 * Module for handling ETH headers
 *
 * @par %Module configuration
 * @code
 *        eth:
 *        {
 *            type = "ETH";
 *            connections = (                                 // based on Ethernet protocol field
 *                            (0x0800, "ip")                  // ip = 0x0800
 *            );
 *
 *            gatewayAddressFile = "conf/gateway_macs.txt";   // The name of the file containing gateway MAC addresses (one address per line) - not needed for Gn config
 *            setEquipmentID = "false";                       // Set equipment ID of each packet to the MAC address of the subscriber (default: false)
 *        };
 * @endcode
 */
class ETH : public captool::Module
{
    public:
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit ETH(std::string name);

        /**
         * Destructor.
         */    
        ~ETH();
        
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);

    protected:
        
        void initialize(libconfig::Config* config);
        void configure (const libconfig::Setting & config);
        
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

        /** Stores the list of Ethernet address in a hash table */
        typedef std::tr1::unordered_map <MACAddress::Ptr, bool> MACAddressMap;
        
        /** The list of gateway MAC addresses */
        MACAddressMap _gatewayAddressMap;
        
        bool _useGatewayAddressList;
        
        /** Set MAC address as the equipment ID of each packet */
        bool setEquipmentID;
        
        /** vlan used in length field for vlan tags */
        static const u_int16_t VLAN_TYPE;
};

#endif // __ETH_H__
