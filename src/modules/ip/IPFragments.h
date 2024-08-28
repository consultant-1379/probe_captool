/*
 * IPFragments.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IP_FRAGMENTS_H__
#define __IP_FRAGMENTS_H__

#include <iostream>
#include <sys/types.h>
#include <time.h>
#include <list>
#include <boost/pool/pool_alloc.hpp>

#include "captoolpacket/CaptoolPacket.h"
#include "util/log.h"
#include "util/AutoMem.h"
#include "IPFragmentHole.h"

#define IP_FRAGMENTS_ALLOC_LENGTH 65536

/**
 * Represents a fragmented IP packet
 */
class IPFragments
{
    public:
        
        /**
         * Constructor.
         */
        IPFragments();
        
        /**
         * Destructor.
         */
        ~IPFragments();
    
        /**
         * Initializes the fragment
         *
         * @param timestamp timestamp of the first packet in the fragmented packet
         */
        void initialize(const struct timeval *timestamp);

        /**
         * Adds a fragmented payload to the defragmented IP packet.
         *
         * @param payload pointer to the payload of the fragmented packet
         * @param first offset of the first byte in the original packet
         * @param length length of the fragment
         * @param moreFrags true if there are more fragments behind this fragment
         *
         * @note see RFC815
         */
        void addFragment(const u_char *payload, u_int first, u_int length, bool moreFrags);
        
        /**
         * Returns true if the packet is completely defragmented.
         *
         * @return true if the packet is completely defragmented
         */
        bool isCompleted();

        /**
         * Returns the timestamp of this fragmetned IP packet.
         *
         * @return the timestamp
         */
        struct timeval *getTimestamp();

        /**
         * Returns the payload of the defragmented IP packet
         *
         * @param length location where the length of the packet is to be copied
         *
         * @return pointer to the first byte of the defragmented payload
         *
         * @note should be used only if isCompleted() returs true
         */
        const u_char *getAssembledPayload(u_int *length);

    private:
        
        /**
         * Helper function for removing a hole
         *
         * @param hole hole to be freed or deleted
         */
        static void deleteHole(IPFragmentHole * hole);
        
        /**
         * Removes all holes from the IPFragments
         */
        void emptyHoles();

        /** time of the first received fragment */
        struct timeval         _timestamp;
        
        /** total length of the reassembled fragment */
        u_int                  _totalLength;
        
        /** storage for assembling the payload */
        AutoMem                _payload;
        
        /** type of list for storing IPFragmentHole s */
        typedef std::list<IPFragmentHole *, boost::pool_allocator<IPFragmentHole *> > HolesList;
        
        /** IPFragmentsHole list */
        HolesList  _holes;
        
        friend class IPFragmentsEquals;
        friend class IPFragmentsHasher;
};

inline bool
IPFragments::isCompleted()
{
    return _holes.empty();
}

inline struct timeval*
IPFragments::getTimestamp()
{
    return &_timestamp;
}

inline const u_char *
IPFragments::getAssembledPayload(u_int *length)
{
    return _payload.get(length);
}

#endif // __IP_FRAGMENTS_H__
