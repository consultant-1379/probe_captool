/*
 * SamplingFilterProcessor.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __SAMPLING_FILTER_H__
#define __SAMPLING_FILTER_H__

#include <sstream>
#include <boost/functional/hash.hpp>

#include "FilterProcessor.h"
#include "userid/IMSI.h"

using std::string;

/**
 * Provides statistical sampling on IMSI (or other traffic attributes).
 */
class SamplingFilterProcessor : public FilterProcessor
{
    public:

        /** Identifies the base of statistical sampling */
        enum Type
        {
            IP,
            IMSI
        };

        /**
         * Creates a new instance of SamplingFilterProcessor
         *
         * @param type determines what is the basis of filtering
         * @param ratio determines the ratio of statistical sampling
         */
        SamplingFilterProcessor(Type type, double ratio);

        /**
         * Returns whether a packet of the given flow passes the filter or no
         */
        bool test(const CaptoolPacket *, const Flow *);

        /**
         * Returns whether the given ID passes the filter or no
         */
        bool test(const ID::Ptr id);

    private:

        Type _type;

        unsigned _threshold;

        /** Modulo denominator used to determine pass / fail from modulo division of hash value */
        static const unsigned DENOMINATOR = 1001;
};

inline
SamplingFilterProcessor::SamplingFilterProcessor(Type type, double ratio) :
    FilterProcessor(),
    _type(type)
{
    _threshold = (unsigned) (ratio * DENOMINATOR);
}

inline
bool SamplingFilterProcessor::test(const CaptoolPacket * packet, const Flow *)
{
    if (_type == IMSI) {
        return test(packet->getUserID());
    }

    // No need to implement IP-based statistical sampling,
    // it can be implemented more efficiently in kernel space
    return false;
}

inline
bool SamplingFilterProcessor::test(const ID::Ptr id)
{
    return id ? id->hashValue() % DENOMINATOR <= _threshold : false;
}

#endif /* __SAMPLING_FILTER_H__ */
