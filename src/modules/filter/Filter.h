/*
 * Filter.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FILTER_H__
#define __FILTER_H__

#include <string>
#include <set>
#include <ostream>
#include <libconfig.h++>

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"
#include "FilterProcessor.h"

using std::string;
using std::set;

/**
 * Module performing various filtering on packets.
 * This module provides the framework for specific instances of FilterProcessor
 * to do the real job.
 * @par %Module configuration
 * Example configurations are given for two specific uses:  user sampling and 
 * port based filtering. Configuration for @em user @sampling:
 * @code
 * imsifilter:
 * {
 *     type = "Filter";                                //
 *     connections = (                                 // possible values: noimsi, filtered
 *                     ("pass", "ip2"),                // Packets passing the filter will go there
 *                     ("drop", "null")                // Specify null instead of "ip2" to drop packets where the IMSI cannot be determined
 *     );                                              //
 * 
 *     bypass = true;                                  // Set to true in order to completely ignore the filter and pass all packets without processing
 *     mode = "sampling";                              // Mode selection (sampling | filtering)
 *     filtertype = "imsi";                            // Specifies what to filter on (imsi | tac | ip | port)
 *     ratio = 0.5;                                    // ratio of "imsi's" put to default output
 * };
 * @endcode
 * Configuration for @em port @em filtering:
 * @code
 * packetfilter2:
 * {
 *     type = "Filter";                                //
 *     connections = (                                 //
 *                     ("pass", "flowpacket"),         // Packets passing the filter will go there
 *                     ("drop", "null")                //
 *     );                                              //
 * 
 *     bypass = true;                                  // Set to true in order to completely ignore the filter and pass all packets without processing
 *     mode = "filtering";                             // Mode selection (sampling | filtering)
 *     filtertype = "port";                            // Specifies what to filter on (imsi | tac | ip | port)
 *     invert = true;                                  // Set to true to invert filtering decision
 *     transport = "tcp";                              // Allows further filtering on transport protocol (tcp | udp)
 *     endpoint = "peer";                              // Specifies which endpoint the filtering is applied to (subscriber | peer)
 *     values = [80, 8080, 443];                       // Comma separated set of values for which the filter will pass packets
 * };
 * @endcode
 */
class Filter : public captool::Module
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit Filter(std::string name);

        // inherited from Module
        ~Filter();

        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);

        // inherited from Module
        void getStatus(std::ostream *s, u_long runtime, u_int period);

    protected:

        // inherited from Module
        void initialize(libconfig::Config* config);
        
        virtual void configure (const libconfig::Setting &);

    private:
        
        /**
         * Returns a pointer to a the created filter processor or NULL if the configuration is not valid.
         */
        FilterProcessor * createFilterProcessor(const libconfig::Setting& config);

        /** connection to use for packets passing the filter */
        Module        *_outPass;
        
        /** connection to use for packets not passing the filter */
        Module        *_outDrop;

        /** number of all packets encountered */
        u_long         _allPackets;
        
        /** number of packets allowed to pass */
        u_long         _passedPackets;

        /**
         * When set to true, all packets pass without testing them at the filter processor.
         * In this state, packet counting (pass/drop) is also skipped
         */
        bool           _bypass;

        /** When set to true, filter processor decision is inverted for all packets */
        bool           _invert;

        /** The filter processor instance used to determine pass / drop */
        FilterProcessor * _filterProcessor;

        /** name to be used in the configuration file for "pass" connection */
        static const string PASS_CONNECTION_NAME;
        
        /** name to be used in the configuration file for "drop" connection */
        static const string DROP_CONNECTION_NAME;

        // config values for filter modes
        static const string SAMPLING_FILTER_MODE;
        static const string FILTERING_FILTER_MODE;

        // config values for filter types
        static const string IMSI_FILTER_TYPE;
        static const string TAC_FILTER_TYPE;
        static const string IP_FILTER_TYPE;
        static const string PORT_FILTER_TYPE;
};

#endif // __FILTER_H__
