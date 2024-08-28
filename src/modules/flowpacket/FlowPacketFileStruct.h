/*
 * FlowPacketFileStruct.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOWPACKET_FILE_SRTUCT_H__
#define __FLOWPACKET_FILE_SRTUCT_H__

#include "userid/TBCD.h"

/**
 * Structure for the binary output file of FlowPacket.
 *
 * Actually, this is a header structure  that followed by a number of
 * (uint16_t) focus values for each facet, numbered from 1 to #facets.
 *
 * @note Binary compatibility of packet log files is broken with SVN revisions prior to rXXX.
 */
class FlowPacketFileStruct {
  public:
    /** seconds of the time of the packet (and yes, I know of the impeding peril in 2038) */
    uint32_t      secs;
    /** microseconds of the time of the packet */
    uint32_t      usecs;
    /** source ip address of the packet */
    uint32_t      srcIP;
    /** destination ip address of the packet */
    uint32_t      dstIP;
    /** length of the packet */
    uint32_t      length;
    /** source port of the packet */
    uint16_t      srcPort;
    /** destination port of the packet */
    uint16_t      dstPort;
    /** transport protocol of the packet */
    uint8_t       protocol;
    /** packet direction from the perspective of the subscriber (UL = 'u', DL = 'd', UNKNOWN = ' ') */
    uint8_t       direction;
    
    /** maximum number of bytes in user and equipment IDs */
    static const size_t ID_LENGTH = TBCD::TBCD_STRING_LENGTH;
    
    /** e.g., IMSI (TBCD packed) */
    uint8_t       user [ID_LENGTH];
    
    /** e.g., IMEI (14+1 digits,  16 for IMEISV) or MAC address packed */
    uint8_t       equipment [ID_LENGTH];
    
    /** number of facets (focus values for which follow the FlowPacketFileStruct in output */
    uint8_t       facets;
};

#endif // __FLOWPACKET_FILE_SRTUCT_H__
