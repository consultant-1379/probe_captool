/*
 * ActiveModule.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include "ActiveModule.h"

#include "captoolpacket/CaptoolPacket.h"

using std::string;

namespace captool {

ActiveModule::ActiveModule(string name)
    : Module(name),
      _currentTime(),
      runstate(NOT_STARTED),
      _period(0),
      _nextTime(0)
{
}

void
ActiveModule::start()
{
    if (runstate != NOT_STARTED)
    {
        return;
    }
    CAPTOOL_MODULE_LOG_FINE("start called.")
            
    runstate = STARTED;
    run();
}

void ActiveModule::run()
{
    CaptoolPacket * const captoolPacket = new CaptoolPacket();
    
    CAPTOOL_MODULE_LOG_INFO("started.")
    
    Module *nullModule = ModuleManager::getInstance()->getModule("null");

    while (runstate == STARTED)
    {
        Module* processor = this;

        while (processor != 0 && processor != nullModule)
        {
            CAPTOOL_MODULE_LOG_FINEST("processing Captool Packet by " << *processor->getName() << ".")
            
            processor = processor->process(captoolPacket);

        }
        
        CAPTOOL_MODULE_LOG_FINEST(captoolPacket->describe())
        
        if (! _nextTime) _nextTime = ( (std::time_t) (_currentTime.tv_sec / _period) + 1 ) * _period;
    
        if (!_listeners.empty() && _currentTime.tv_sec >= _nextTime)
        {
            for (std::set<ActiveModuleListener*>::iterator i(_listeners.begin()), end(_listeners.end()); i != end; ++i)
                (*i)->time(&_currentTime);
            
            do _nextTime += _period; 
            while (_nextTime <= _currentTime.tv_sec);
        }
    }
    
    delete(captoolPacket);
    
    CAPTOOL_MODULE_LOG_INFO("stopped.")
}

void
ActiveModule::stop()
{
    if (runstate == STOPPED)
    {
        return;
    }
    
    CAPTOOL_MODULE_LOG_INFO("stop called.")
            
    runstate = STOPPED;
    
    interrupted();
}

void
ActiveModule::finished()
{
    CAPTOOL_MODULE_LOG_INFO("finished called.")
            
    runstate = STOPPED;
}

void
ActiveModule::addListener(ActiveModuleListener* listener)
{
    if (listener) _listeners.insert(listener);
}

void
ActiveModule::setPeriod(std::time_t period)
{
    _period = period;
    
    if (_nextTime) /* do not restart timer before the first packet */
        _nextTime = ( (std::time_t) (_currentTime.tv_sec / _period) + 1 ) * _period;
}

} // namespace captool
