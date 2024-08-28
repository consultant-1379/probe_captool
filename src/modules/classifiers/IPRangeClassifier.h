/*
 * IPRangeClassifier.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IP_RANGE_CLASSIFIER_H__
#define __IP_RANGE_CLASSIFIER_H__

#include <string>
#include <map>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#include "classification/ClassificationMetadata.h"
#include "classification/Classifier.h"
#include "classification/Signature.h"
#include "classification/Hintable.h"

using std::string;
using std::map;

/**
 * Module performing port-based application classification
 */
class IPRangeClassifier : public captool::Module, public Classifier
{
    public:

        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */
        explicit IPRangeClassifier(string name);

        /**
         * Destructor.
         */
        ~IPRangeClassifier();

        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);

    protected:

        // inherited from Module
        void initialize(libconfig::Config* config);

        // Inherited from Classifier
        void registerSignature(unsigned blockId, const Signature * signature);

    private:

        typedef struct
        {
            u_int32_t   address; // in host byte order
            u_int32_t   netmask; // in host byte order
        } IPRange;

        /** Maps IP ranges to hints */
        multimap<Hintable::Hint,IPRange> _ipRangeMap;
};

#endif // header
