/*
 * ActiveModuleListener.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __ACTIVE_MODULE_LISTENER_H__
#define __ACTIVE_MODULE_LISTENER_H__

#include <sys/types.h>

/**
 * Listener interface for active modules
 */
class ActiveModuleListener
{
    public:
        
        /**
         * Destructor.
         */
        virtual ~ActiveModuleListener();
        
        /**
         * Method called by ActiveModule at each period
         *
         * @param time current time at ActiveModule at the time of call
         */
        virtual void time(const struct timeval *time) = 0;
};

inline
ActiveModuleListener::~ActiveModuleListener()
{
}

#endif // __ACTIVE_MODULE_LISTENER_H__
