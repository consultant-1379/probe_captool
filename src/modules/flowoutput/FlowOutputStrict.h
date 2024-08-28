/*
 * FlowOutputStrict.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_OUTPUT_STRICT_H__
#define __FLOW_OUTPUT_STRICT_H__

#include <string>

#include "libconfig.h++"

#include "modules/gtpcontrol/GTPControl.h"

#include "flow/Flow.h"
#include "flow/FlowID.h"
#include "flow/FlowIDEqualsStrict.h"
#include "FlowModule.h"

using namespace captool;
using std::string;

/**
 * Module for producing flow information with well defined uplink/downlink directions.
 *
 * @par %Module configuration specific to FlowOutputStrict -- for global options, see FlowModule
 * @code
 *        flow:
 *        {
 *            type = "FlowOutputStrict";                      // FlowOutputStrict is the preferred Flow module. However, when packet direction information is not available
 *                                                            // (either from GTP-C messages or gateway MAC addresses), than you have to fall back to FlowOutput.
 *
 *            gtpControlModule = "gtpc";                      // to associate userId (IMSI) and equipementId (IMEI) to flows (only used when 3GDTHack is set to true)
 *            directTunnelHack = false;                       // Indicates whether user and equipment IDs need to be assigned to flows and packets based on user IP addresses. 
 *                                                            // This is required in 3GDT configs where non-3GDT user plane traffic is captured from the IuPS and not from the Gn
 *                                                            // (hence PDP binding cannot be done based on TEIDs extracted from GTP-C)
 *        };
 * @endcode
 */
class FlowOutputStrict : public FlowModule<Flow,FlowIDEqualsStrict>
{
    
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit FlowOutputStrict(std::string name);
        
        /**
         * Destructor.
         */    
        virtual ~FlowOutputStrict();
        
        // inherited from Module
        void getStatus(std::ostream *s, u_long runtime, u_int period);

        // inherited from FileGenerator
        void openNewFiles();
        
    protected:
        
        // inherited from Module
        virtual void initialize(libconfig::Config* config);

        // inherited from FlowModule
        virtual void preprocess(CaptoolPacket * packet, FlowID::Ptr flowid) throw(DirectionUnknownException);
        
        // inherited from FlowModule
        virtual void postprocess(CaptoolPacket * packet, Flow::Ptr flow);

        // inherited from FlowModule
        virtual bool isUplink(CaptoolPacket * packet, Flow::Ptr flow);
        
    private:
        /** the GTPControl module that could be requested for the IMSI (from PDPContext) of an IP */
        GTPControl *_gtpControlModule;
        
        /** Total number of bytes with known user ID during the current period */
        u_int64_t _userIdentifiedBytes;

        /** Total number of bytes with known equipment ID during the current period */
        u_int64_t _equipmentIdentifiedBytes;
        
        /** Total number of bytes that could only be assigned to IMSI via user IP */
        u_int64_t _3GDTHackBytes;
        
        /** 
         * Indicates whether user and equipment IDs need to be assigned to flows and packets based on user IP addresses. 
         * This is required in 3GDT configs where non-3GDT user plane traffic is captured from the IuPS and not from the Gn
         * (hence PDP binding cannot be done using GTP-C)
         */
        bool _3GDTHack;
};

#endif // __FLOW_OUTPUT_STRICT_H__
