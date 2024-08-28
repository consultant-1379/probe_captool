/*
 * log.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CAPTOOL_LOG_H__
#define __CAPTOOL_LOG_H__

/**
 * Defines macros for logging messages.
 */


#include <iostream>

#define CAPTOOL_LOG_LEVEL_OFF     10000
#define CAPTOOL_LOG_LEVEL_SEVERE   1000
#define CAPTOOL_LOG_LEVEL_WARNING   900
#define CAPTOOL_LOG_LEVEL_CONFIG    800
#define CAPTOOL_LOG_LEVEL_INFO      700
#define CAPTOOL_LOG_LEVEL_FINE      500
#define CAPTOOL_LOG_LEVEL_FINER     400
#define CAPTOOL_LOG_LEVEL_FINEST    300
#define CAPTOOL_LOG_LEVEL_ALL         0

#ifndef CAPTOOL_LOG_LEVEL
#define CAPTOOL_LOG_LEVEL CAPTOOL_LOG_LEVEL_CONFIG
#endif // CAPTOOL_LOG_LEVEL

#ifndef CAPTOOL_LOG_OUTPUT
#define CAPTOOL_LOG_OUTPUT std::cerr
#endif

#if (CAPTOOL_LOG_LEVEL <= CAPTOOL_LOG_LEVEL_SEVERE)
    #define CAPTOOL_LOG_SEVERE(msg) \
    { CAPTOOL_LOG_OUTPUT << "\033[0;31;49m" << "SEVERE:  " << msg << "\033[0m" << std::endl; }
#else
    #define CAPTOOL_LOG_SEVERE(msg) \
    {}
#endif

#if (CAPTOOL_LOG_LEVEL <= CAPTOOL_LOG_LEVEL_WARNING)
    #define CAPTOOL_LOG_WARNING(msg) \
    { CAPTOOL_LOG_OUTPUT << "\033[0;31;49m" << "WARNING: " << msg << "\033[0m" << std::endl; }
#else
    #define CAPTOOL_LOG_WARNING(msg) \
    {}
#endif

#if (CAPTOOL_LOG_LEVEL <= CAPTOOL_LOG_LEVEL_INFO)
    #define CAPTOOL_LOG_INFO(msg) \
    { CAPTOOL_LOG_OUTPUT << "\033[0;32;49m" << "INFO:    " << msg << "\033[0m" << std::endl; }
#else
    #define CAPTOOL_LOG_INFO(msg) \
    {}
#endif

#if (CAPTOOL_LOG_LEVEL <= CAPTOOL_LOG_LEVEL_CONFIG)
    #define CAPTOOL_LOG_CONFIG(msg) \
    { CAPTOOL_LOG_OUTPUT << "\033[0;34;49m" << "CONFIG:  " << msg << "\033[0m" << std::endl; }
#else
    #define CAPTOOL_LOG_CONFIG(msg) \
    {}
#endif

#if (CAPTOOL_LOG_LEVEL <= CAPTOOL_LOG_LEVEL_FINE)
    #define CAPTOOL_LOG_FINE(msg) \
    { CAPTOOL_LOG_OUTPUT << "\033[0;37;49m" << "FINE:    " << msg << "\033[0m" << std::endl; }
#else
    #define CAPTOOL_LOG_FINE(msg) \
    {}
#endif

#if (CAPTOOL_LOG_LEVEL <= CAPTOOL_LOG_LEVEL_FINER)
    #define CAPTOOL_LOG_FINER(msg) \
    { CAPTOOL_LOG_OUTPUT << "\033[0;37;49m" << "FINER:   " << msg << "\033[0m" << std::endl; }
#else
    #define CAPTOOL_LOG_FINER(msg) \
    {}
#endif


#if (CAPTOOL_LOG_LEVEL <= CAPTOOL_LOG_LEVEL_FINEST)
    #define CAPTOOL_LOG_FINEST(msg) \
    { CAPTOOL_LOG_OUTPUT << "\033[0;37;49m" << "FINEST:  " << msg << "\033[0m" << std::endl; }
#else
    #define CAPTOOL_LOG_FINEST(msg) \
    {}
#endif

#endif // __CAPTOOL_LOG_H__
