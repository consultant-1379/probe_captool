/*
 * FileGenerator.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FILE_GENERATOR_H__
#define __FILE_GENERATOR_H__

namespace captool {

/**
 * Interface for classes generating file outputs to allow registering at FileManager.
 */    
class FileGenerator
{
    public:
        
        /**
         * Destructor.
         */
        virtual ~FileGenerator() {}
        
        /**
         * Requests FileGenerator to close its current open output file and open a new one.
         */
        virtual void openNewFiles() = 0;
};

} // namespace captool

#endif // __FILE_GENERATOR_H__
