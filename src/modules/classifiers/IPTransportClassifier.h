/*
 * IPTransportClassifier.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IPTransportClassifier_H__
#define __IPTransportClassifier_H__

#include <string>
#include <ostream>
#include <set>

#include <pcre.h>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#include "classification/Signature.h"
#include "classification/ClassificationMetadata.h"
#include "classification/Classifier.h"


using std::string;

/**
 * Module for performing classification of non UDP/TCP traffic based on IP protocol value
 */
class IPTransportClassifier : public captool::Module, public Classifier
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit IPTransportClassifier(string name);
        
        /**
         * Destructor.
         */    
        ~IPTransportClassifier();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
    protected:
        
        // inherited from Module
        void initialize(libconfig::Config* config);
        
        // Inherited from Classifier
        void registerSignature(unsigned blockId, const Signature * signature);

    private:

        /** Binds a hint to the corresponding IP protocol values */
        typedef std::map<u_int8_t, Hintable::Hint> HintMap;
        
        HintMap _hintMap;
};

#endif // __IPTransportClassifier_H__
