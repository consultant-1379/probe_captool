/*
 * UserFilterProcessor.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __USER_FILTER_H__
#define __USER_FILTER_H__

#include <set>
#include <sstream>

#include "FilterProcessor.h"

using std::set;
using std::string;

class UserFilterProcessor : public FilterProcessor
{
    public:

        /**
         * Creates a new UserFilterProcessor
         *
         * @param values the set of strings for which the filter will return "pass"
         */
        UserFilterProcessor(set<string> values);

        /**
         * Returns whether a packet of the given flow passes the filter or no
         */
        bool test(const CaptoolPacket *, const Flow *);

    private:

        /** the set of strings for which the filter returns "pass" */
        set<string>     _values;
};

inline
UserFilterProcessor::UserFilterProcessor(set<string> values) :
    FilterProcessor(),
    _values(values)
{
}

inline bool
UserFilterProcessor::test(const CaptoolPacket * packet, const Flow *)
{
    const ID::Ptr & id = packet->getUserID();
    if (! id) return false;

    set<string>::const_iterator it = _values.find(id->str());

    return it != _values.end();
}

#endif /* __USER_FILTER_H__ */
