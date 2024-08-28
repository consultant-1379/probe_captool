/*
 * Timestamped.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __TIMESTAMPED_H__
#define __TIMESTAMPED_H__

#include <ctime>

/** Interface for objects holding timestamps. */
class Timestamped
{
    /** Return timestamp of last activity of the object. */
    virtual const struct timeval getLastTimestamp() const = 0;
};
        
#endif
