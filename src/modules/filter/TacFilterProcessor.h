/*
 * TacFilterProcessor.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __TAC_FILTER_PROCESSOR_H__
#define __TAC_FILTER_PROCESSOR_H__

#include <set>
#include <typeinfo> // bad_cast
#include "FilterProcessor.h"
#include "userid/IMEISV.h"

using std::set;
using std::string;

class TacFilterProcessor : public FilterProcessor
{
    public:

        /**
         * Creates a new TacFilterProcessor
         *
         * @param values the set of strings for which the filter will return "pass"
         */
        TacFilterProcessor(set<string> values);

        /**
         * Returns whether a packet of the given flow passes the filter or no
         */
        bool test(const CaptoolPacket *, const Flow *);

    private:

        /** the set of strings for which the filter returns "pass" */
        set<string>     _values;
};

inline
TacFilterProcessor::TacFilterProcessor(set<string> values) :
    FilterProcessor(),
    _values(values)
{
}

inline bool
TacFilterProcessor::test(const CaptoolPacket * pkt, const Flow *)
{
    try {
        const ID::Ptr & id = pkt->getEquipmentID();
        if (! id)
            return false;
        IMEISV * imei = dynamic_cast<IMEISV*> (id.get());
        if (! imei)
            return false;
        set<string>::const_iterator it = _values.find(imei->tac());
        return it != _values.end();
    } catch (std::bad_cast) {}
    return false;
}

#endif /* __TAC_FILTER_PROCESSOR_H__ */
