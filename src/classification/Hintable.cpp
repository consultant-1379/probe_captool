/*
 * Hintable.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <sstream>

#include "Hintable.h"
#include <utility>

#include "ClassificationMetadata.h"

using std::pair;

Hintable::Hintable() {}

Hintable::~Hintable() {}

bool
Hintable::setHint(unsigned blockId, unsigned hintId)
{
    bool firstOccurence = true;
    Hint hint = std::make_pair(blockId, hintId);
    unsigned count = 1;
    HintContainer::iterator it = hints.find(hint);
    if (it != hints.end())
    {
        count += it->second;
        hints.erase(it);
        firstOccurence = false;
    }
    hints.insert(std::make_pair(hint, count));
    return firstOccurence;
}

const
Hintable::HintContainer&
Hintable::getHints() const
{
    return hints;
}

std::ostream& 
operator<<(std::ostream& o, const Hintable& h)
{
    if (!h.hints.empty())
    {
        o << "|hints={";
        for (Hintable::HintContainer::const_iterator i = h.hints.begin(); i != h.hints.end(); ++i)
        {
            if (i != h.hints.begin())
            {
                o << ",";
            }
            o << "(" << ClassificationMetadata::getInstance().getBlockIdMapper().getName(i->first.first) << "," << i->first.second << "," << i->second << ")";
        }
        o << "}";
    }

    return o;
}
