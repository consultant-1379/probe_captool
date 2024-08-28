/*
 * Captool.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CAPTOOL_H__
#define __CAPTOOL_H__

#include <pcap.h>
#include <fstream>
#include <ctime>

#include "modulemanager/activemodule/ActiveModule.h"
#include "modulemanager/activemodule/ActiveModuleListener.h"
#include "filemanager/FileGenerator.h"
#include "libconfig.h++"

/**
 * Namespace of the main Captool classes
 */
namespace captool
{

/**
 * The main application executable
 */
class Captool : public ActiveModuleListener, public FileGenerator
{
    public:
        
        /**
         * Returns a singleton.
         *
         * @return the singleton of Captool
         */
	static Captool* getInstance();
        
        /**
         * Destroys the singleton.
         */
        static void destroyInstance();
        
        /**
         * Initializes captool: loads config, loads modules, starts active module.
         */
        void initialize();
        
        /**
         * Starts the ActiveModule.
         */
        void start();
        
        /**
         * Stops the ActiveModule.
         */
        void stop();

        // inherited from ActiveModuleListener
        void time(const struct timeval *time);
        
        // inherited from FileGenerator
        void openNewFiles();
        
    private:

        /**
         * Constructor
         */
	Captool();

        /**
         * Destructor. Destroys ModuleManager singleton
         */
	~Captool();

	/** to prevent copying */
        Captool(const Captool&);

        /** to prevent copying */
        Captool& operator= (const Captool&);
        
        /** singleton instance */
        static Captool* _instance;

        /** config object representing the config file */
        libconfig::Config _config;

        /** prefix of the output file */
        std::string       _statusLogFilePrefix;
        
        /** postfix of the output file */
        std::string       _statusLogFilePostfix;

        /** stream to write the output file to */
        std::ofstream     _statusLogFileStream;
        
        /** /proc entry for memory usage checking */
        std::ifstream     procfile;
        
        /** true if Captool should generate status logs */
        bool              _doStatusLog;

        /** interval of periodic timer events */
        std::time_t       _timerPeriod;
        
        /** path and name of the configuration file */
        static const std::string CONFIG_FILE;
};
} // namespace captool

/**
 * Function for handling interrupts.
 *
 * @param interrupt the interrupt signal no.
 */
void interrupted(int interrupt);

/**
 * Main function. Initializes and starts Captool.
 *
 * @param argc number of arguments (including executable name)
 * @param argv input arguments
 *
 * @return the exit code of the program
 */
int main(int argc, char* argv[]);

#endif // __CAPTOOL_H__
