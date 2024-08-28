/*
 * PortClassifier.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PORT_CLASSIFIER_H__
#define __PORT_CLASSIFIER_H__

#include <string>
#include <map>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#include "classification/ClassificationMetadata.h"
#include "classification/Classifier.h"
#include "classification/Signature.h"
#include "classification/Hintable.h"

/**
 * Module performing port-based application classification
 */
class PortClassifier : public captool::Module, public Classifier
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit PortClassifier(std::string name);
        
        /**
         * Destructor.
         */    
        ~PortClassifier();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
    protected:
        
        // inherited from Module
        void initialize(libconfig::Config* config);

        // Inherited from Classifier
        void registerSignature(unsigned blockId, const Signature * signature);

    private:
    
        typedef std::map<u_int16_t, Hintable::Hint> PortMap;
    
        /** Maps TCP port numbers to block ID */
        PortMap tcpPorts;
        
        /** Maps UDP port numbers to block ID */
        PortMap udpPorts;
};

#endif // __PORT_CLASSIFIER_H__
