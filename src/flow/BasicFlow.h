/*
 * BasicFlow.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __BASIC_FLOW_H__
#define __BASIC_FLOW_H__

#include <ostream>

#include <string>

#include <time.h>

#include <boost/shared_ptr.hpp>

#include "util/poolable.h"
#include "util/Timestamped.h"
#include "flow/FlowID.h"

/**
 * Class representing basic properties of a TCP or UDP flow.
 */
class BasicFlow : public Timestamped
{

    public:
        
        /**
         * Constructor.
         *
         * @param id the FlowID of the flow
         */
        BasicFlow(const FlowID::Ptr & id);
        
        /**
         * Destructor.
         */
        virtual ~BasicFlow();
        
        /** Pointer type for safe exchange of flow pointers */
        typedef boost::shared_ptr<BasicFlow> Ptr;
        
        /**
         * Registers a packet in the flow.
         *
         * @param timestamp timestamp of the registered packet
         * @param upload true if the packet is sent upstream, false if it is sent downstream
         * @param length length of the sent packet
         */
        virtual void packet(const struct timeval *timestamp, bool upload, unsigned long length);
        
        /** Return time of last packet arrival in the flow. */
        const struct timeval getLastTimestamp() const;
        
        /** Get pointer to the associated FlowID object. */
        const FlowID::Ptr & getID() const;
        
        /** Return number of uploaded bytes in the flow. */
        unsigned long getUploadBytes() const;
        
        /** Return number of downloaded bytes in the flow. */
        unsigned long getDownloadBytes() const;
        
        /** Return number of uploaded packets in the flow. */
        unsigned long getUploadPackets() const;
        
        /** Return number of downloaded packets in the flow. */
        unsigned long getDownloadPackets() const;
        
        /**
         * Returns the registered number of packets in the flow (both upstream and downstream)
         *
         * @return the number of packets in the flow
         */
        u_int getPacketsNumber();

        CAPTOOL_POOLABLE_DECLARE_METHODS()
        
        friend std::ostream& operator<<(std::ostream&, const BasicFlow&);
        
    protected:
        
        /** first registered packet's time */
        struct timeval         _firstPacket;
        
        /** last registered packet's time */
        struct timeval         _lastPacket;
        
        /** FlowID of the flow */
        FlowID::Ptr      _id;
        
        /** uploaded bytes */
        u_long                 _uploadBytes;
        
        /** downloaded bytes */
        u_long                 _downloadBytes;
        
        /** number of uploaded packets */
        u_long                 _uploadPackets;
        
        /** number of downloaded packets */
        u_long                 _downloadPackets;
        
        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(BasicFlow)

inline
BasicFlow::BasicFlow(const FlowID::Ptr & id)
    : _firstPacket(),
      _lastPacket(),
      _id(id),
      _uploadBytes(0),
      _downloadBytes(0),
      _uploadPackets(0),
      _downloadPackets(0)
{
}

inline
BasicFlow::~BasicFlow()
{
}

inline void
BasicFlow::packet(const struct timeval *timestamp, bool upload, u_long length)
{
    assert(timestamp != 0);
    
    _lastPacket = *timestamp;
    if (_firstPacket.tv_sec == 0 && _firstPacket.tv_usec == 0) _firstPacket = _lastPacket; // won't work for __very__ old traces :)
    
    if (upload)
    {
        _uploadBytes += length;
        ++_uploadPackets;
    }
    else
    {
        _downloadBytes += length;
        ++_downloadPackets;
    }
};

inline u_int
BasicFlow::getPacketsNumber()
{
    return (_uploadPackets + _downloadPackets);
}

inline
const struct timeval 
BasicFlow::getLastTimestamp() const
{
    return _lastPacket;
}

inline
const FlowID::Ptr &
BasicFlow::getID() const
{
    return _id;
}

inline
unsigned long 
BasicFlow::getUploadBytes() const
{
    return _uploadBytes;
}

inline
unsigned long 
BasicFlow::getDownloadBytes() const
{
    return _downloadBytes;
}

inline
unsigned long 
BasicFlow::getUploadPackets() const
{
    return _uploadPackets;
}

inline
unsigned long 
BasicFlow::getDownloadPackets() const
{
    return _downloadPackets;
}

#endif // __BASIC_FLOW_H__
