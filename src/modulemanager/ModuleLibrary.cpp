/*
 * ModuleLibrary.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <dlfcn.h>
#include <iostream>
#include <cstdlib>

#include "util/log.h"

#include "ModuleLibrary.h"

using std::string;

namespace captool
{

const string ModuleLibrary::LIBRARY_FILE_PREFIX = "lib";
const string ModuleLibrary::LIBRARY_FILE_POSTFIX = ".so";
const string ModuleLibrary::MODULE_LIBRARY_DIR = "lib/";
const string ModuleLibrary::MODULE_CREATOR_FUNCTION_PREFIX = "create";    
    
ModuleLibrary::ModuleLibrary(string libraryName)
    : _libraryName(libraryName),
      _libraryHandle(0),
      _creatorFunction(0)
{

    // generate filename for library
    string fileName = MODULE_LIBRARY_DIR + LIBRARY_FILE_PREFIX + _libraryName + LIBRARY_FILE_POSTFIX;
    
    CAPTOOL_LOG_FINER("ModuleLibrary opening module library " << fileName << ".")
            
// if captool and the modules are statically linked, there is no need for opening the .so files
#ifndef  CAPTOOL_STATIC_BUILD
            
    // open library
    _libraryHandle = dlopen(fileName.c_str(), RTLD_NOW);

    if (_libraryHandle == 0) {
        CAPTOOL_LOG_SEVERE("ModuleLibrary unable to load library " << fileName << " (" << dlerror() << ").")
        exit(-1);
    }

    // generate creator function name
    string functionName = MODULE_CREATOR_FUNCTION_PREFIX + _libraryName;
    
    // link to creator function
    void* creator = dlsym(_libraryHandle, functionName.c_str());
    _creatorFunction = reinterpret_cast<Module *(*)(string)>(creator);
    
    if (_creatorFunction == 0) {
        CAPTOOL_LOG_SEVERE("ModuleLibrary unable to create link to creator function in library " << libraryName << ", in file " << fileName << " (" << dlerror() << ").")
        exit(-1);
    }
    
#endif // CAPTOOL_STATIC_BUILD
}

Module*
ModuleLibrary::createInstance(string instanceName)
{
    assert(_creatorFunction != 0);

    // creates instance
    Module* instance = _creatorFunction(instanceName);
    
    // error
    if (instance == 0) {
        CAPTOOL_LOG_SEVERE("ModuleLibrary unable to create instance " << instanceName << ".")
        exit(-1);
    }

    CAPTOOL_LOG_FINER("ModuleLibrary created instance of " << _libraryName << " named \"" << instanceName << "\".")
    
    return instance;
}

ModuleLibrary::~ModuleLibrary()
{
    //close library
//NOTE: if the libraries are closed, valgrind is unable to find function references    
#ifndef DEBUG
    if (_libraryHandle != 0) {
        
        CAPTOOL_LOG_FINER("ModuleLibrary closing library " << _libraryName)

        dlclose(_libraryHandle);
        _libraryHandle = 0;
    }
#endif
}

} // namespace captool
