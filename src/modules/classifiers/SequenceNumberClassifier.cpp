/*
 * SequenceNumberClassifier.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "SequenceNumberClassifier.h"

#include <iostream>
#include <sstream>

DEFINE_CAPTOOL_MODULE(SequenceNumberClassifier)

const string SequenceNumberClassifier::SEQUENCE_NUMBER_DATA_PARAMETER_NAME_PREFIX = "sequence_no_";

SequenceNumberClassifier::SequenceNumberClassifier(string name)
    :  Module(name)
{
}

SequenceNumberClassifier::~SequenceNumberClassifier()
{
}

void
SequenceNumberClassifier::initialize(libconfig::Config* config)
{
    assert(config != 0);

    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);

    // Register the sequence-number meta signature
    registerSignatures("sequence-number");
}

Module*
SequenceNumberClassifier::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);

    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    Flow * flow = captoolPacket->getFlow().get();
    if (!flow)
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }

    u_int8_t transportType = flow->getID()->getProtocol();

    // Sequence number matching is only meaningfull for UDP traffic
    if (transportType != IPPROTO_UDP)
    {
        return _outDefault;
    }

    size_t payloadLength = 0;
    const u_char * payload = captoolPacket->getPayload(&payloadLength);

    // Go through each registered sequence classifier descriptor
    for (map<Hintable::Hint,SequenceClassifierDescriptor>::const_iterator it = _classifierMap.begin(); it != _classifierMap.end(); ++it)
    {
        Hintable::Hint hint = it->first;
        unsigned position = it->second.position;
        unsigned size = it->second.size;
        unsigned count = it->second.count;
        bool hostByteOrder = it->second.hostByteOrder;

        if (payloadLength < position + size)
        {
            continue;
        }

        unsigned long sequenceNumber = 0;
        if (hostByteOrder)
        {
            switch (size)
            {
                case 2:     sequenceNumber = (payload[position+1] << 8) + payload[position]; break;
                case 4:     sequenceNumber = (payload[position+3] << 24) + (payload[position+2] << 16) + (payload[position+1] << 8) + payload[position]; break;
                default:    continue; // Should not happen
            }
        }
        else
        {
            switch (size)
            {
                case 2:     sequenceNumber = (payload[position] << 8) + payload[position+1]; break;
                case 4:     sequenceNumber = (payload[position] << 24) + (payload[position+1] << 16) + (payload[position+2] << 8) + payload[position+3]; break;
                default:    continue; // Should not happen
            }
        }

        // Retrieve previous sequence number statistics of this flow
        // The name of the parameter is SEQUENCE_NUMBER_DATA_PARAMETER_NAME_PREFIX + "@" + position + ":" + size
        std::stringstream s(SEQUENCE_NUMBER_DATA_PARAMETER_NAME_PREFIX);
        s << "@" << position << ":" << size;
        Parameter * parameter = flow->getParameter(s.str());
        SequenceNumberData * rtpData = dynamic_cast<SequenceNumberData *> (parameter);
        if (parameter == 0)
        {
            rtpData = new SequenceNumberData();
            flow->setParameter(s.str(), rtpData);
        }
        assert(rtpData != 0); // Fails if registered parameter is not an SequenceNumberData object. Should not happen.

        unsigned numberOfSubsequentPackets = rtpData->update(sequenceNumber, captoolPacket->getDirection());
        if (numberOfSubsequentPackets >= count)
        {
            flow->setHint(hint.first, hint.second);
        }
    }

    return _outDefault;
}

void
SequenceNumberClassifier::registerSignature(unsigned blockId, const Signature * signature)
{
    Hintable::Hint hint = std::make_pair(blockId, signature->getId());
    SequenceClassifierDescriptor descriptor;

    // No need to check existence of attributes, this had already been performed by the DTD
    std::istringstream(signature->getXmlDefinition()->get_attribute_value("position")) >> descriptor.position;
    std::istringstream(signature->getXmlDefinition()->get_attribute_value("size")) >> descriptor.size;
    std::istringstream(signature->getXmlDefinition()->get_attribute_value("count")) >> descriptor.count;
    descriptor.hostByteOrder = signature->getXmlDefinition()->get_attribute_value("host-byte-order") == "true";
    
    CAPTOOL_MODULE_LOG_INFO("Sequence number signature " << hint.second << " for block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId) << 
                                ": position=" << descriptor.position << ", size=" << descriptor.size << ", count=" << descriptor.count)

    _classifierMap.insert(std::make_pair(hint, descriptor));
}

