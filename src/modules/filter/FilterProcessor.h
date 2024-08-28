/*
 * FilterProcessor.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FILTER_PROCESSOR_H__
#define __FILTER_PROCESSOR_H__

#include "captoolpacket/CaptoolPacket.h"
#include "flow/Flow.h"

using captool::CaptoolPacket;

/**
 * Base class for all filter processors making "pass" or "drop" decisions for each individual packet.
 */
class FilterProcessor
{
    public:

        FilterProcessor() {};

        virtual bool test(const CaptoolPacket *, const Flow *) = 0;
};

#endif /* __FILTER_PROCESSOR_H__ */
