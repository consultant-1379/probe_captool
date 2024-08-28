/*
 * ActiveModule.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __ACTIVE_MODULE_H__
#define __ACTIVE_MODULE_H__

#include <string>
#include <set>
#include <ctime>

#include "modulemanager/Module.h"
#include "ActiveModuleListener.h"

namespace captool {

/**
 * The module that is generating the values for CaptoolPacket objects. It should be the first module in the module chain.
 */    
class ActiveModule : public Module
{
    public:
        
        /**
         * Starts this ActiveModule. The module runs until it is finished (indicated by calling finished()),
         * or is stopped by calling stop().
         */    
        void start();
        
        /**
         * Stops running this ActiveModule.
         */
        void stop();
        
        /**
         * Sets the period the ActiveModule should trigger its listener.
         *
         * @param period the value in seconds
         */
        void setPeriod(std::time_t period);
        
        /**
         * Returns the current time measured by ActiveModule.
         *
         * @return current time
         */
        const struct timeval *getTime();
        
        /**
         * Sets the listener of this ActiveModule.
         *
         * @param listener the listener to be triggered at each period
         */
        void addListener(ActiveModuleListener* listener);
        
    protected:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit ActiveModule(std::string name);

        /**
         * Destructor.
         */    
        virtual ~ActiveModule() {}

        /**
         * The implementation should call this method, thus notifying that it has finished processing.
         */
        void finished();
        
        /**
         * This method is called when stop() is called on the module, thus notifying the implementation.
         */
        virtual void interrupted() = 0;
        
        /** holds the value of current time. The implementation must use this variable for storing current time */
        struct timeval _currentTime;
        
    private:

        /**
         * The thread method that runs ActiveModule.
         */
        void run();
        
        enum RunState
        {
            /** packet capture not yet started;  it can only be started from this state */
            NOT_STARTED,
            
            /** packet capture started */
            STARTED,
            
            /** activity stopped */
            STOPPED,
        }
            /** Indicates whether the ActiveModule should be running. */
            runstate;
        
        /** listeners of the ActiveModule waiting for periodic notifications */
        std::set<ActiveModuleListener*> _listeners;
        
        /** the period in seconds the listener should be triggered */
        std::time_t _period;
        
        /** next time in seconds the listener should be triggered */
        std::time_t _nextTime;

};


inline const struct timeval *
ActiveModule::getTime()
{
    return &_currentTime;
};

} // namespace captool

#endif // __ACTIVE_MODULE_H__
