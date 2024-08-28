/*
 * Flow.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "Flow.h"
#include "util/log.h"

CAPTOOL_POOLABLE_INIT_POOL(Flow, 10000)

std::ostream& 
operator<<(std::ostream& o, const Flow& flow)
{
    return o << (StatFlow&) flow << "|" << flow._userId << "|" << flow._equipmentId << "|" << (FacetClassified&) flow;
}

bool
Flow::setHint(unsigned blockId, unsigned hintId)
{
    bool firstOccurence = Hintable::setHint(blockId, hintId);
    if (firstOccurence)
    {
        // If this was the first occurence of this hint for this flow...
        _lastHintedPacket = _uploadPackets + _downloadPackets;
    }
    return firstOccurence;
}

void
Flow::setTags(const TagContainer& newTags, unsigned blockId, bool final = false)
{
    bool stateBefore = isFinal();
    FacetClassified::setTags(newTags, blockId, final);
    bool stateAfter = isFinal();
    if (!stateBefore && stateAfter)
    {
        _firstFinalClassifiedPacket = _uploadPackets + _downloadPackets;
    }
}

void
Flow::setUserID(const ID::Ptr & id)
{
    _userId = id;
}

void
Flow::setEquipmentID(const ID::Ptr & id)
{
    _equipmentId = id;
}

namespace std { namespace tr1 {

template<>
std::size_t
hash<Flow::Ptr>::operator()(Flow::Ptr b) const
{
    return (std::size_t) b.get();
}

}} // std::tr1::
