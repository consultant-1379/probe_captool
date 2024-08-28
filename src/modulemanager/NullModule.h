/*
 * NullModule.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __NULL_MODULE_H__
#define __NULL_MODULE_H__

#include <string>

#include "Module.h"

namespace captool {

/**
 * Empty module that can be returned as an alternative to 0 in Module::process.
 */
class NullModule : public Module
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit NullModule(std::string name);
        
        // inherited from Module
        ~NullModule();
};

inline
NullModule::NullModule(std::string name)
    : Module(name)
{
}

inline
NullModule::~NullModule()
{
}

} // namespace captool

#endif // __NULL_MODULE_H__
