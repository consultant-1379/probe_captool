/*
 * FlowOutput.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_OUTPUT_H__
#define __FLOW_OUTPUT_H__

#include <string>

#include "flow/Flow.h"
#include "flow/FlowIDEquals.h"
#include "FlowModule.h"

using namespace captool;

/**
 * Module for producing flow information.
 */
class FlowOutput : public FlowModule<Flow,FlowIDEquals>
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit FlowOutput(std::string name);
        
        /**
         * Destructor.
         */    
        virtual ~FlowOutput();
        
        // inherited from Module
        void getStatus(std::ostream *s, u_long runtime, u_int period);
        
        // inherited from FileGenerator
        void openNewFiles();
        
    protected:

        // inherited from FlowModule
        virtual bool isUplink(CaptoolPacket * packet, Flow::Ptr flow);
};

#endif // __FLOW_OUTPUT_H__
