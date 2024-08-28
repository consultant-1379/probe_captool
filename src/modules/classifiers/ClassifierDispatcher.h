/*
 * ClassifierDispatcher.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CLASSIFIER_DISPATCHER_H__
#define __CLASSIFIER_DISPATCHER_H__

#include <string>
#include <ostream>
#include <libconfig.h++>
#include <boost/dynamic_bitset.hpp>

#include "classification/ClassificationMetadata.h"
#include "classification/Classifier.h"
#include "captoolpacket/CaptoolPacket.h"

/**
 * Entry point to the traffic classification part of Captool.
 * Its purpose is to dispatch incoming packets between the different (DPI) 
 * modules until a final classification decision is made by a ClassAssigner.
 * @par %Module configuration
 * @code
 *   dispatcher:
 *   {
 *       type = "ClassifierDispatcher";
 *
 *       connections = (
 *                       ("nonUdpTcpFirstPacket", "transportclassifier"),   // First packet of non UDP or TCP traffic
 *                       ("nonUdpTcp", "summary"),                          // Any non UDP or TCP traffic (except first packet of "flow")
 *                       ("firstPacket", "portclassifier"),                 // First packet of each flow
 *                       ("firstReply", "serverportsearch"),                // First reply packet of each flow
 *                       ("firstFinal", "serverportsearch"),                // First packet of each flow where the flow is alread classified as final
 *                       ("unclassified", "http"),
 *                       ("classified", "summary"),                         // Classified packets, no more classification required
 *                       ("recheck", "serverportsearch")                    // Classified packet, but recheck every n = recheckFrequency packet
 *       );
 *
 *       minPackets = 10;                                // Min number number of packets to be classified per flow (even if a "sure" hint is available earlier)
 *       maxPackets = 40;                                // Max number number of packets to be classified per flow (even if a "sure" hint is not yet available)
 *       recheckFrequency = 100;                         // Re-check classification every nth packet in the flow
 *   };
 * @endcode
 */
class ClassifierDispatcher : public captool::Module, public Classifier
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit ClassifierDispatcher(std::string name);

        // inherited from Module
        ~ClassifierDispatcher();

        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);

        // inherited from Module
        void getStatus(std::ostream *s, u_long runtime, u_int period);

    protected:

        void initialize(libconfig::Config* config);
        
        virtual void configure (const libconfig::Setting &);
        
    private:
    
        /** Minimum number of packets to be examined per flow by the classification system (even if a "sure" hint is available earlier) */
        unsigned    _minPackets;
        
        /** Maximum number of packets to be examined per flow by the classification system (even if a "sure" hint is still not available) */
        unsigned    _maxPackets;
        
        /** Specify frequencey of classification recheck (e.g. if set to 1000, then recheck will be performed for every 1000th packet of the flow) */
        unsigned    _recheckFrequency;
        
        /** connection to use for the first packet of flows with transports other than UDP or TCP */
        Module        *_outNonUdpTcpFirstPacket;
        
        /** connection to use for flows with transports other than UDP or TCP */
        Module        *_outNonUdpTcp;
        
        /** connection to use for already classified flows */
        Module        *_outClassified;
        
        /** connection to use for unclassified flows (except when this is the first packet of the flow) */
        Module        *_outUnclassified;

        /** connection to use for flows to be rechecked */
        Module        *_outRecheck;

        /** connection to use for the first packet of flows where the flow is already classified as final */
        Module        *_outFirstFinalPacket;

        /** connection to use for the first reply packet of flows */
        Module        *_outFirstReplyPacket;
        
        /** connection to use for the first packet of flows */
        Module        *_outFirstPacket;
        
        /** name to be used in the configuration file for nonUdpTcpFirstPacket connection */
        static const std::string NON_UDP_TCP_FIRST_PACKET_CONNECTION_NAME;
        
        /** name to be used in the configuration file for nonUdpTcp connection */
        static const std::string NON_UDP_TCP_CONNECTION_NAME;
        
        /** name to be used in the configuration file for classified connection */
        static const std::string CLASSIFIED_CONNECTION_NAME;
        
        /** name to be used in the configuration file for recheck connection */
        static const std::string RECHECK_CONNECTION_NAME;
        
        /** name to be used in the configuration file for unclassified connection */
        static const std::string UNCLASSIFIED_CONNECTION_NAME;

        /** name to be used in the configuration file for first reply packet connection */
        static const std::string FIRST_FINAL_PACKET_CONNECTION_NAME;

        /** name to be used in the configuration file for first final packet connection */
        static const std::string FIRST_REPLY_PACKET_CONNECTION_NAME;

        /** name to be used in the configuration file for first packet connection */
        static const std::string FIRST_PACKET_CONNECTION_NAME;
};

#endif // __CLASSIFIER_DISPATCHER_H__
