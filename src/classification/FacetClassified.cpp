/*
 * FacetClassified.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "FacetClassified.h"
#include "util/log.h"
#include "classification/ClassificationMetadata.h"


FacetClassified::FacetClassified() 
    :   _cachedFinalState(false),
        _cachedFinalStateValid(false)
{
    size_t size = ClassificationMetadata::getInstance().getFacetIdMapper().size();
    
    _tags = TagContainer(size);
    _finalFlags = dynamic_bitset<>(size + 1);
}

FacetClassified::~FacetClassified()
{
}

void
FacetClassified::setTag(unsigned tagId, unsigned tagValue, bool final = false)
{
    unsigned previousTagValue = _tags.getTag(tagId);
    
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();

    if (_finalFlags.test(tagId))
    {
        if (previousTagValue != tagValue)
        {
            CAPTOOL_LOG_WARNING("Attempting to modify final tag for object @" <<(size_t)this<<
                "; facet: " << cmd.getFacetIdMapper().getName(tagId) << 
                ", previous (final) value: " << cmd.getFocusIdMapper().getName(previousTagValue) <<
                ", new value: " << cmd.getFocusIdMapper().getName(tagValue))
        }
        // If this tag is already set as final, than it should not be modified
        return;
    }

    if (previousTagValue > 0)
    {
        if (tagValue == 0)
        {
            CAPTOOL_LOG_INFO("Resetting tag value for object @" << (int)this << 
                "; facet: " << cmd.getFacetIdMapper().getName(tagId) << 
                ", previous value: " << cmd.getFocusIdMapper().getName(previousTagValue))
        }
        else if (previousTagValue != tagValue)
        {
            CAPTOOL_LOG_INFO("Conflicting tag value being set for object @" << (int)this << 
                "; facet: " << cmd.getFacetIdMapper().getName(tagId) << 
                ", previous value: " << cmd.getFocusIdMapper().getName(previousTagValue) <<
                ", new value: " << cmd.getFocusIdMapper().getName(tagValue))
        }

    }

    _tags.setTag(tagId, tagValue);
    _finalFlags.set(tagId, final);

    // Invalidate cached final state
    _cachedFinalStateValid = false;
}

void
FacetClassified::setTags(const TagContainer& newTags, unsigned blockId, bool final = false)
{
    for (unsigned i = 1; i <= _tags.size(); i++)
    {
        unsigned tagValue = newTags.getTag(i);
        if (tagValue > 0)
        {
            setTag(i, tagValue, final);
        }
    }

    if (final)
    {
        _finalBlockIds.insert(blockId);
    }

    // Invalidate cached final state
    _cachedFinalStateValid = false;
}

bool 
FacetClassified::isFinal() const
{
    if (!_cachedFinalStateValid)
    {
        dynamic_bitset<> mask = ClassificationMetadata::getInstance().getFinalMask();
        _cachedFinalState = (_finalFlags & mask) == mask;
        _cachedFinalStateValid = true;
    }

    return _cachedFinalState;
}


std::ostream& 
operator<<(std::ostream& o, const FacetClassified& f)
{
    o << "tags={";
    bool first = true;
    for (unsigned i=1; i<=f._tags.size(); i++)
    {
        unsigned tagValue = f._tags.getTag(i);
        if (tagValue > 0)
        {
            if (!first)
            {
                o << ",";
            }
            else 
            {
                first = false;
            }
            o << ClassificationMetadata::getInstance().getFacetIdMapper().getName(i) << "=" << ClassificationMetadata::getInstance().getFocusIdMapper().getName(tagValue);
        }
    }
    o << "}";
    
    return o;
}
