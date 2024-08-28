/*
 * PacketStatistics.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "PacketStatistics.h"

#include <cmath>

using std::sqrt;

PacketStatistics::PacketStatistics()
    : _firstPacketUL(),
      _firstPacketDL(),
      _lastPacketUL(),
      _lastPacketDL(),
      _iatSqrSumDL(0),
      _iatSqrSumUL(0),
      _sizeSqrSumDL(0),
      _sizeSqrSumUL(0),
      _packetsUL(0),
      _packetsDL(0),
      _bytesUL(0),
      _bytesDL(0)
{}

std::ostream& operator<<(std::ostream& o, const PacketStatistics& stats)
{
    double avgSizeUL = stats._packetsUL > 0 ? (double)stats._bytesUL / stats._packetsUL : 0;
    double avgSizeDL = stats._packetsDL > 0 ? (double)stats._bytesDL / stats._packetsDL : 0;
    double devSizeUL = stats._packetsUL > 0 ? sqrt((double)stats._sizeSqrSumUL / stats._packetsUL - avgSizeUL * avgSizeUL) : 0;
    double devSizeDL = stats._packetsDL > 0 ? sqrt((double)stats._sizeSqrSumDL / stats._packetsDL - avgSizeDL * avgSizeDL) : 0;
    double avgIatUL = stats._packetsUL > 1 ? (stats._lastPacketUL.tv_sec - stats._firstPacketUL.tv_sec + (stats._lastPacketUL.tv_usec - stats._firstPacketUL.tv_usec) / 1e6) / (stats._packetsUL-1) : 0;
    double avgIatDL = stats._packetsDL > 1 ? (stats._lastPacketDL.tv_sec - stats._firstPacketDL.tv_sec + (stats._lastPacketDL.tv_usec - stats._firstPacketDL.tv_usec) / 1e6) / (stats._packetsDL-1) : 0;
    double devIatUL = stats._packetsUL > 2 ? sqrt(stats._iatSqrSumUL / (stats._packetsUL-1) - avgIatUL * avgIatUL) : 0;
    double devIatDL = stats._packetsDL > 2 ? sqrt(stats._iatSqrSumDL / (stats._packetsDL-1) - avgIatDL * avgIatDL) : 0;
    
    return o << avgSizeUL << "|" << avgSizeDL << "|" << devSizeUL << "|" << devSizeDL << "|" << avgIatUL << "|" << avgIatDL << "|" << devIatUL << "|" << devIatDL;
}

void
PacketStatistics::packet(const struct timeval *timestamp, bool upload, unsigned long length)
{
    if (upload)
    {
        _packetsUL++;
        _bytesUL += length;
        _sizeSqrSumUL += length * length;
        if (_packetsUL == 1)
        {
            _firstPacketUL = *timestamp;
        }
        else
        {
            double iatUL = timestamp->tv_sec - _lastPacketUL.tv_sec + (timestamp->tv_usec - _lastPacketUL.tv_usec) / 1e6;
            _iatSqrSumUL += iatUL * iatUL;
        }
        _lastPacketUL = *timestamp;
    }
    else
    {
        _packetsDL++;
        _bytesDL += length;
        _sizeSqrSumDL += length * length;
        if (_packetsDL == 1)
        {
            _firstPacketDL = *timestamp;
        }
        else
        {
            double iatDL = timestamp->tv_sec - _lastPacketDL.tv_sec + (timestamp->tv_usec - _lastPacketDL.tv_usec) / 1e6;
            _iatSqrSumDL += iatDL * iatDL;
        }
        _lastPacketDL = *timestamp;
    }
};
