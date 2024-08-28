/*
 * gtp.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __GTP_H__
#define __GTP_H__

#include <sys/types.h>

/**
 * Structure of a gtp header without options.
 */
struct gtp_header
{
    /** flags */
    u_int8_t     flags;
#define GTP_VER_MASK      0xe0
#define GTP_PROT_MASK     0x10
#define GTP_EXT_MASK      0x04
#define GTP_SEQ_MASK      0x02
#define GTP_NPDU_MASK     0x01
#define GTP_OPTS_MASK     0x07    
    /** message type */
    u_int8_t     type;
    /** payload length */
    u_int16_t    length;
    /** tunnel endpoint identifier */
    u_int32_t    teid;
};

/**
 * Structure of a gtp header with options.
 */
struct gtp_header_opt
{
    /** flags */
    u_int8_t     flags;
    /** message type */
    u_int8_t     type;
    /** payload length */
    u_int16_t    length;
    /** tunnel endpoint identifier */
    u_int32_t    teid;
    /** sequence number */
    u_int16_t    seq;
    /** npdu */
    u_int8_t     npdu;
    /** next extension header */
    u_int8_t     ext;
};


#define GTP_HEADER_CORE_LENGTH                8
#define GTP_HEADER_OPTS_LENGTH                4
#define GTP_HEADER_CORE_WITH_OPTS_LENGTH     12

#endif // __GTP_H__
