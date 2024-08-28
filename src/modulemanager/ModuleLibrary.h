/*
 * ModuleLibrary.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __MODULE_LIBRARY_H__
#define __MODULE_LIBRARY_H__

#include <string>

#include "Module.h"

namespace captool
{

class Module;    

/**
 * ModuleLibrary wraps shared object files containing Captool Modules
 */
class ModuleLibrary
{
    public:
        
        /**
         * Returns the name of the shared object wrapped by this handler.
         *
         * @return pointer to the name of this library
         */
        const std::string *getName();
        
    protected:
        
        /**
         * Constructor
         *
         * @param libraryName name of the library (a file named lib<libraryName>.so will be searched for)
         */
        explicit ModuleLibrary(std::string libraryName);
        
        /**
         * Destructor.
         */
        ~ModuleLibrary();
        
        /**
         * Creates an instance of the Module represented by this library.
         *
         * @param instanceName the unique name of the instance to be created
         *
         * @return pointer to the created module
         */    
        Module* createInstance(std::string instanceName);
        
        friend class ModuleManager;
        
    private:
        
        /** name of the library */
        std::string _libraryName;
        
        /** handle to the opened shared library */
        void* _libraryHandle;
        
        /** pointer to the creator function in the shared library (defined in the Module.h) */
        Module* (*_creatorFunction)(std::string);
        
        /** prefix of library file names */
        static const std::string LIBRARY_FILE_PREFIX;
        
        /** postfix and extension of library file names */
        static const std::string LIBRARY_FILE_POSTFIX;
        
        /** name of the library directory */
        static const std::string MODULE_LIBRARY_DIR;
        
        /** prefix of the creator function */
        static const std::string MODULE_CREATOR_FUNCTION_PREFIX;
};

inline const std::string *
ModuleLibrary::getName()
{
    return &_libraryName;
}

} // namespace captool

#endif // __MODULE_LIBRARY_H__
