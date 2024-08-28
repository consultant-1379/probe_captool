/*
 * ClassificationConstraints.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include "ClassificationConstraints.h"

ClassificationConstraints::Constraint
ClassificationConstraints::getConstraintID(string constraintName)
{
    if (constraintName == "rtp-header") return ClassificationConstraints::RTP_HEADER;
    else if (constraintName == "unidirectional-flow") return ClassificationConstraints::UNIDIRECTIONAL_FLOW;
    else if (constraintName == "symmetric-flow") return ClassificationConstraints::SYMMETRIC_FLOW;
    else if (constraintName == "first-ul-packet") return ClassificationConstraints::FIRST_UL_PACKET;
    else if (constraintName == "first-dl-packet") return ClassificationConstraints::FIRST_DL_PACKET;
    else return ClassificationConstraints::UNKNOWN;
}

bool
ClassificationConstraints::evaluateConstraint(ClassificationConstraints::Constraint constraintID, const CaptoolPacket * captoolPacket)
{
    assert(captoolPacket != 0);
    size_t payloadLength = 0;
    const u_char * payload = captoolPacket->getPayload(&payloadLength);
    const Flow * flow = captoolPacket->getFlow().get();
    assert(flow != 0);

    switch (constraintID)
    {
        case ClassificationConstraints::RTP_HEADER: return evaluateRtpFlags(payload, payloadLength);
        case ClassificationConstraints::UNIDIRECTIONAL_FLOW: return evaluateUnidirectionalFlow(flow);
        case ClassificationConstraints::SYMMETRIC_FLOW: return evaluateSymmetricFlow(flow);
        case ClassificationConstraints::FIRST_UL_PACKET: return flow->getUploadPackets() == 1;
        case ClassificationConstraints::FIRST_DL_PACKET: return flow->getDownloadPackets() == 1;
        default: assert(false); // Should not get here
    }
}

bool
ClassificationConstraints::evaluateRtpFlags(const u_char * payload, u_int payloadLength)
{
    if (payloadLength < 12) return false; // Min RTP header length
    return (payload[0] & 0xc0) == 0x80;  // Check that RTP version = 2 (http://books.google.com/books?id=zGVVuO-6w3IC&pg=PA431)
}

bool
ClassificationConstraints::evaluateUnidirectionalFlow(const Flow * flow)
{
    unsigned maxOtherDirectionPackets = 1;
    double maxOtherDirectionPacketRatio = 0.01;
    unsigned long dlPackets = flow->getDownloadPackets();
    unsigned long ulPackets = flow->getUploadPackets();

    if (dlPackets > ulPackets)
    {
        return ulPackets <= maxOtherDirectionPackets || maxOtherDirectionPacketRatio * dlPackets > ulPackets;
    }
    else
    {
        return dlPackets <= maxOtherDirectionPackets || maxOtherDirectionPacketRatio * ulPackets > dlPackets;
    }
}

bool
ClassificationConstraints::evaluateSymmetricFlow(const Flow * flow)
{
    double minRatio = 0.9;
    double maxRatio = 1 / minRatio;
    unsigned long dlPackets = flow->getDownloadPackets();
    unsigned long ulPackets = flow->getUploadPackets();

    return (double)ulPackets / dlPackets < maxRatio && (double)ulPackets / dlPackets > minRatio;
}
