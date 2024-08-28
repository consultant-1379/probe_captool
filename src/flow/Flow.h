/*
 * Flow.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_H__
#define __FLOW_H__

#include <cassert>
#include <string>
#include <ostream>
#include <tr1/functional>
#include <boost/shared_ptr.hpp>

#include "util/poolable.h"
#include "userid/ID.h"
#include "flow/FlowID.h"
#include "flow/StatFlow.h"
#include "flow/OptionsContainer.h"
#include "flow/ParametersContainer.h"
#include "classification/Hintable.h"
#include "classification/FacetClassified.h"

using std::string;

/**
 * Provides a detailed representation of a TCP or UDP flow 
 * (including user and equipement ID, classification info and custom options).
 */
class Flow : public StatFlow, public FacetClassified, public Hintable, public OptionsContainer, public ParametersContainer
{
    public:
        
        /**
         * Constructor.
         *
         * @param id the FlowID of the flow
         */
        Flow(const FlowID::Ptr &);
        
        /**
         * Destructor.
         */
        ~Flow();

        const ID::Ptr getUserID() const;

        const ID::Ptr getEquipmentID() const;
        
        /**
         * Set user ID associated with the flow
         */
        void setUserID(const ID::Ptr & id);
        
        /**
         * Set equipment ID associated with the flow
         */
        void setEquipmentID(const ID::Ptr & id);
        
        /** Convenience type for safe pointers to Flow instances */
        typedef boost::shared_ptr<Flow>    Ptr;

        /** Inherited from Hintable */
        bool setHint(unsigned blockId, unsigned hintId);
        
        /** Inherited from FacetClassified */
        void setTags(const TagContainer& newTags, unsigned blockId, bool final);

        /** Returns the number of the last packet in the flow for which a new hint has been registered */
        u_long getLastHintedPacketNumber() const;
        
        /** Returns the number of the first packet in the flow which has been classified as final */
        u_long getFirstFinalClassifiedPacketNumber() const;
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()
        
    private:

        /** String representation of the ID of the user (e.g. IMSI) */
        ID::Ptr _userId;
        
        /** String representation of the ID of the user equipment (e.g. MAC address or IMEI ) */
        ID::Ptr _equipmentId;
        
        /** packet count (UL + DL) in the flow when the last hint was registered to the flow */
        u_long _lastHintedPacket;
        
        /** packet count (UL + DL) in the flow when the flow was first classified as final */
        u_long _firstFinalClassifiedPacket;
        
        friend std::ostream& operator<<(std::ostream&, const Flow&);
        
        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(Flow)

namespace std { namespace tr1 {
    template<> std::size_t hash<Flow::Ptr>::operator()(Flow::Ptr) const;
}}

inline
Flow::Flow(const FlowID::Ptr & id)
    : StatFlow(id),
      _lastHintedPacket(0),
      _firstFinalClassifiedPacket((u_long)-1)
{
}

inline
Flow::~Flow()
{
}

inline
const ID::Ptr
Flow::getUserID() const
{
    return _userId;
}

inline
const ID::Ptr
Flow::getEquipmentID() const
{
    return _equipmentId;
}

inline
u_long
Flow::getLastHintedPacketNumber() const
{
    return _lastHintedPacket;
}

inline
u_long
Flow::getFirstFinalClassifiedPacketNumber() const
{
    return _firstFinalClassifiedPacket;
}

#endif // __FLOW_H__
