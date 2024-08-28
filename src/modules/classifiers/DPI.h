/*
 * DPI.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __DPI_H__
#define __DPI_H__

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
 * Module for performing DPI signature matching
 */
class DPI : public captool::Module, public Classifier
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit DPI(string name);
        
        /**
         * Destructor.
         */    
        ~DPI();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        // inherited from Module
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);

    protected:
        
        // inherited from Module
        void initialize(libconfig::Config* config);
        
        // Inherited from Classifier
        void registerSignature(unsigned blockId, const Signature * signature);

    private:

        /** Binds a hint to the corresponding signature regexp */
        typedef std::map<Hintable::Hint,pcre*> SignatureMap;
        
        SignatureMap signatureMapTCP;

        SignatureMap signatureMapUDP;
};

#endif // __DPI_H__
