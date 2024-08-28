/*
 * Classifier.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CLASSIFIER_H__
#define __CLASSIFIER_H__

#include <string>

#include "util/log.h"
#include "classification/ClassificationMetadata.h"

using std::string;

/** Base class of all classifier modules */
class Classifier
{
    public:
        
        Classifier();
        
    protected:
        
        /** 
         * Query from ClassificationMetadata signatures of the given type and register them through the registerSignature method
         *
         * @param type the type of signatures to be registered. If omitted, than all signatures will be registered
         */
        void registerSignatures(const string type = "");
        
        /** 
         * Register the given signature 
         *
         * @param blockId the ID of the block within which the signature has been defined
         * @param signature reference to the signature to be registered
         */
        virtual void registerSignature(unsigned blockId, const Signature * signature);
};

inline void
Classifier::registerSignature(unsigned, const Signature *)
{
}

#endif // __CLASSIFIER_H__