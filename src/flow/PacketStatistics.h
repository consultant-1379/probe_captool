/*
 * PacketStatistics.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PACKET_STATISTICS_H__
#define __PACKET_STATISTICS_H__

#include <sys/time.h>
#include <ostream>

/**
 * Tracks basic statistics (average and standard deviation) of packet size and packet inter-arrival time in a flow (separately for UL and DL).
 */
class PacketStatistics
{
    public:

        /** Constructor*/
        PacketStatistics();

        /** Destructor*/
        ~PacketStatistics() {}
    
        /**
         * Registers a packet in the flow.
         *
         * @param timestamp timestamp of the registered packet
         * @param upload true if the packet is sent upstream, false if it is send downstream
         * @param length length of the sent packet
         */
        void packet(const struct timeval *timestamp, bool upload, unsigned long length);

    private:
    
        /** timestamp of first UL packet */
        struct timeval            _firstPacketUL;

        /** timestamp of first DL packet */
        struct timeval            _firstPacketDL;

        /** timestamp of last UL packet */
        struct timeval            _lastPacketUL;

        /** timestamp of last DL packet */
        struct timeval            _lastPacketDL;

        /** Square sum of IATs for DL packets */
        double                    _iatSqrSumDL;
        
        /** Square sum of IATs for UL packets */
        double                    _iatSqrSumUL;
        
        /** Square sum of packet sizes for DL packets */
        unsigned long             _sizeSqrSumDL;
        
        /** Square sum of packet sizes for UL packets */
        unsigned long             _sizeSqrSumUL;
        
        /** Number of packets in UL direction (duplicates BasicFlow functionality, but it is cleaner this way...) */
        unsigned long             _packetsUL;

        /** Number of packets in DL direction (duplicates BasicFlow functionality, but it is cleaner this way...) */
        unsigned long             _packetsDL;

        /** Number of bytes in UL direction (duplicates BasicFlow functionality, but it is cleaner this way...) */
        unsigned long             _bytesUL;

        /** Number of bytes in DL direction (duplicates BasicFlow functionality, but it is cleaner this way...) */
        unsigned long             _bytesDL;
        
        friend std::ostream& operator<<(std::ostream&, const PacketStatistics&);
};

#endif // header
