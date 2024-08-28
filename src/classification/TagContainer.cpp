/*
 * TagContainer.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "TagContainer.h"
#include "ClassificationMetadata.h"

TagContainer::TagContainer() : _size(0), dirty(true) {}

TagContainer::TagContainer(size_t n) 
    : _size(n),
      dirty(true)
{
    tags = std::vector<unsigned>(n+1);
    _definedFacets = dynamic_bitset<>(n+1);
}

TagContainer::TagContainer(const TagContainer& tagContainer)
{
    tags = std::vector<unsigned>(tagContainer.tags);
    _size = tagContainer._size;
    _definedFacets = dynamic_bitset<>(tagContainer._definedFacets);
    dirty = tagContainer.dirty;
    hash = tagContainer.hash;
    repr = tagContainer.repr;
    empty = tagContainer.empty;
}

TagContainer::~TagContainer() {}

bool
TagContainer::equals(const TagContainer &o) const
{
    if (tags.size() != o.tags.size()) 
    {
        return false;
    }
    else 
    {
        for (unsigned i=0; i<tags.size(); i++)
        {
            if (tags[i] != o.tags[i])
            {
                return false;
            }
        }
    }
    
    return true;
}

size_t
TagContainer::hashCode() const
{
    if (dirty) update();
    return hash;
}

std::string
TagContainer::str() const
{
    if (dirty) update();
    return repr;
}

bool
TagContainer::isEmpty() const
{
    if (dirty) update();
    return empty;
}

void
TagContainer::update() const
{
    if (dirty)
    {
        repr.clear();
        hash = 0;
        empty = true;
        for (std::size_t i = 1; i <= _size; ++i)
        {
            if (tags[i] > 0) empty = false;
            // Hash code algorithm of java.util.List
            hash = hash * 31 + tags[i];
            if (i > 1) repr.append("\t");
            repr.append(tags[i] ? ClassificationMetadata::getInstance().getFocusIdMapper().getName(tags[i]) : "\\N");
        }
        dirty = false;
    }
}
