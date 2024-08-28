/*
 * Module.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __MODULE_H__
#define __MODULE_H__

#include "util/log.h"

#define CAPTOOL_MODULE_LOG_SEVERE(msg) \
    CAPTOOL_LOG_SEVERE(_name << ": " << msg)
#define CAPTOOL_MODULE_LOG_WARNING(msg) \
    CAPTOOL_LOG_WARNING(_name << ": " << msg)
#define CAPTOOL_MODULE_LOG_INFO(msg) \
    CAPTOOL_LOG_INFO(_name << ": " << msg)
#define CAPTOOL_MODULE_LOG_CONFIG(msg) \
    CAPTOOL_LOG_CONFIG(_name << ": " << msg)
#define CAPTOOL_MODULE_LOG_FINE(msg) \
    CAPTOOL_LOG_FINE(_name << ": " << msg)
#define CAPTOOL_MODULE_LOG_FINER(msg) \
    CAPTOOL_LOG_FINER(_name << ": " << msg)
#define CAPTOOL_MODULE_LOG_FINEST(msg) \
    CAPTOOL_LOG_FINEST(_name << ": " << msg)


#include <ostream>
#include <list>
#include <libconfig.h++>
#include <pcap.h>

#include "ModuleManager.h"
#include "flow/Flow.h"
#include "util/Configurable.h"

namespace captool
{

class CaptoolPacket;    

/**
 * Base of packet processing classes in Captool.
 * Most notably, it provides the process() method that is called for each
 * captured packet for one or more Modules as defined by the module 
 * configuration.
 * 
 * @par %Module configuration (common elements for all Modules; should be put
 * into the @c modules section):
 * @code
 *   nnnnnn:            // name of the module, e.g., `flow'
 *   {
 *     type = "xxxxx";  // name of the Module class for this module, e.g., `FlowOutput'
 *   };
 * @endcode
 *
 * @par Example configuration (@em modules section):
 * @code
 *   modules:
 *   {
 *     gtpu:
 *     {
 *       type = "GTPUser";
 *       connections = (
 *                       (255, "imsifilter")
 *                     );
 *       gsnIPModule = "ip";
 *       gtpControlModule = "gtpc";
 *     };
 *   };
 * @endcode
 */
class Module : public Configurable
{
    public:
        
        /**
         * Returns the unique name of the module.
         *
         * @return pointer to the name of the string
         */
        const std::string *getName();
        
        /**
         * Allows the module to process the actual packet.
         * The result of the processing is the next module to process the packet.
         *
         * @param captoolPacket the CaptoolPacket to be processed
         *
         * @return the next Module to handle the CaptoolPacket,
         * or 0 or the Null module if the CaptoolPacket is to be discarded
         */
        virtual Module* process(CaptoolPacket *captoolPacket);
        
        /**
         * Allows the module to process a flow when it times out.
         * The result of the processing is the next module to process the flow.
         *
         * @param flow a pointer to the Flow to be processed
         *
         * @return the next Module to handle the flow,
         * or 0 or the Null module if no further processing is required for the flow
         */
        virtual Module* process(const Flow * flow);
        
        /**
         * Returns a one-liner on the current status of the module.
         *
         * @param s the output stream to write the status to
         * @param runtime the time Captool has been running in seconds
         * @param period the period between two status requests in seconds
         */
        virtual void getStatus(std::ostream *s, u_long runtime, u_int period);
        
        /**
         * Allows the module to fix its protocolheader in the CaptoolPacket.
         *
         * @param captoolPacket the CaptoolPacket
         */
        virtual void fixHeader(CaptoolPacket *captoolPacket);
        
        /**
         * Describe its own protocol in the CaptoolPacket in a one-liner. Used for debugging.
         *
         * @param captoolPacket the CaptoolPacket
         * @param s the output stream to write the description to
         */
        virtual void describe(const CaptoolPacket *captoolPacket, std::ostream *s);
        
        /**
         * Returns the pcap data link type to be used if this is the base module of a capture file
         */
        virtual int getDatalinkType();
        
        /** Name of the default connection to be used in the coniguration file */
        static const std::string DEFAULT_CONNECTION_NAME;
        
    protected:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit Module(std::string name);
        
        /**
         * Initializes the module based on the input configuration.
         * The abstract class initializes the default output module parameter.
         */    
        virtual void initialize(libconfig::Config *config);
        
        virtual void configure (const libconfig::Setting & config);
        
        /**
         * Destructor
         */
        virtual ~Module() {}
        
        /** unique name of the given module */
        std::string _name;

        /** default output Module of this module */
        Module* _outDefault;
        
        friend class ModuleManager;
    
};

inline const std::string*
Module::getName()
{
    return &_name;
}

} // namespace captool

/**
 * Definition of a Captool Module.
 * This definition must be placed into each Module to be used with Captool.
 * The module must be compiled into a file named  libModulename.so
 *
 * @param moduleName the name of the module.
 */
#define DEFINE_CAPTOOL_MODULE( moduleName ) \
extern "C" { \
captool::Module* create##moduleName(std::string name) \
{ \
    return new moduleName(name); \
} \
} // extern "C"

#endif // __MODULE_H__
