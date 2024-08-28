/*
 * SequenceNumberClassifier.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __SEQUENCE_NUMBER_CLASSIFIER_H__
#define __SEQUENCE_NUMBER_CLASSIFIER_H__

#include <string>
#include <map>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#include "classification/ClassificationMetadata.h"
#include "classification/Classifier.h"
#include "classification/Signature.h"
#include "classification/Hintable.h"

#include "SequenceNumberData.h"

#include "flow/Flow.h"

using std::map;
using std::string;
using captool::Module;
using captool::CaptoolPacket;

/**
 * Module to detect aplication class based on incrementing sequence numbers within a flow (e.g. for RTP, or IPSec NAT traversal).
 */
class SequenceNumberClassifier : public Module, public Classifier
{
    public:

        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */
        explicit SequenceNumberClassifier(std::string name);

        /**
         * Destructor.
         */
        ~SequenceNumberClassifier();

        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);

    protected:

        // inherited from Module
        void initialize(libconfig::Config* config);

        // Inherited from Classifier
        void registerSignature(unsigned blockId, const Signature * signature);

    private:

        typedef struct {
            unsigned position;  // Position of sequence number in the packet
            unsigned size;      // Size of sequence number in bytes (can be 2 or 4)
            unsigned count;     // Minimum number of strictly incrementing sequence numbers in subsequent packets
            bool hostByteOrder; // True if host byte order is used instead of the default network byte order
        } SequenceClassifierDescriptor;

        static const string SEQUENCE_NUMBER_DATA_PARAMETER_NAME_PREFIX;

        map<Hintable::Hint, SequenceClassifierDescriptor> _classifierMap;
};


#endif // header
