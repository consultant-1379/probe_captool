/*
 * Configurable.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CONFIGURABLE_H__
#define __CONFIGURABLE_H__

/**
 * Interface for configurable components using libconfig structures
 * (e.g., modules, managers).
 */
class Configurable
{
        
        /**
         * Initializes the object based on input configuration.
         *
         * @param config the configuration descriptor
         */    
        virtual void initialize(libconfig::Config *config) = 0;
        
        /**
         * Runtime reconfiguration of module.
         * @param config configuration setting for this module (must be a group)
         */
        virtual void configure (const libconfig::Setting & config) = 0;
};
        
#endif
