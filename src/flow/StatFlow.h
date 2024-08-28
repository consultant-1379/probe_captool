/*
 * StatFlow.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __STAT_FLOW_H__
#define __STAT_FLOW_H__

#include <map>
#include <ostream>

#include "FlowID.h"
#include "BasicFlow.h"
#include "PacketStatistics.h"

#include <boost/shared_ptr.hpp>

/**
 * TCP / UDP flow with statistics.
 */
class StatFlow : public BasicFlow
{
    public:
        
        /**
         * Constructor.
         *
         * @param id the FlowID of the flow
             */
        StatFlow(const FlowID::Ptr & id);
        
        /**
         * Destructor.
        */
        virtual ~StatFlow();
        
        /** Pointer type for safe exchange of flow pointers */
        typedef boost::shared_ptr<StatFlow> Ptr;
        
        /**
         * Registers a packet in the flow.
         *
         * @param timestamp timestamp of the registered packet
         * @param upload true if the packet is sent upstream, false if it is send downstream
         * @param length length of the sent packet
         */
        virtual void packet(const struct timeval *timestamp, bool upload, unsigned long length);
        
        /** Return current estimate for packet inter arrival time. */
        double getIAT() const;
        
        /** Enables and starts collection of detailed packet statistics */
        void enableDetailedStatistics();
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()
                
    protected:
        
        /** inter arrival time (seconds) */
        double                    iat;
        
        /** Pointer to object collecting detailed statistics or NULL if such statistics are not to be collected */
        PacketStatistics *        _statistics;
        
        CAPTOOL_POOLABLE_DECLARE_POOL()

        friend std::ostream& operator<<(std::ostream&, const StatFlow&);
};

CAPTOOL_POOLABLE_DEFINE_METHODS(StatFlow)

inline
StatFlow::StatFlow(const FlowID::Ptr & id)
    : BasicFlow(id),
      _statistics(NULL)
{
}

inline
StatFlow::~StatFlow()
{
    delete _statistics;
}

inline double
StatFlow::getIAT() const
{
    return iat;
}

#endif // __STAT_FLOW_H__
