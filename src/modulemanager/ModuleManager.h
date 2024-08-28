/*
 * ModuleManager.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __MODULE_MANAGER_H__
#define __MODULE_MANAGER_H__

#include <sstream>
#include <string>
#include <map>
#include <pcap.h>
#include <libconfig.h++>
#include <boost/asio.hpp>

#include "ModuleLibrary.h"
#include "filemanager/FileManager.h"

namespace captool
{

class Module;    
class ActiveModule;
class ModuleLibrary;

/**
 * Manages creation and configuration of Modules.
 *
 * ModuleManager searches Captool configuration for module entries, loads
 * required libraries, creates modules, and initializes them using the full
 * configuration.  For an example configuration see Module#config.
 *
 * ModuleManager allows for runtime adjustment of Modules through a socket
 * interface.  The control client (e.g. a simple telnet client) can connect to
 * it and send a new configuration for any Module, referenced by the module's
 * name.  Modules wishing to be changeable this way should override the 
 * Module::configure() method.  
 *
 * @note ModuleManager listens for commands on a separate thread.  Modules
 * implementing Module::configure() should ensure thread safety.
 *
 * @note Indication that a configuration setting was accepted by any given 
 * module is currently only evident from a subsequent log message by that
 * same module.
 *
 * @par Configuration
 * Configuration entries of ModuleManager should be put under section named 
 * @c moduleManager:
 * @code
 *   moduleManager: {
 *     activeModule = "capture";   // name of ActiveModule receiving each packet first
 *
 *     port = 44444;               // port on which captool listens for control commands
 *                                 // or 0 for nocontrol interface
 *   };
 * @endcode
 */
class ModuleManager
{
    public:
        
        /** type for list of module instances */
        typedef std::list<Module*> ModuleList;
	
        /**
         * Singleton accessor.
         *
         * @return singleton of ModuleManager
         */
        static ModuleManager *getInstance();

        /**
         * Returns the registered ActiveModule
         *
         * @return the ActiveModule
         */
        ActiveModule *getActiveModule();
        
        /**
         * Returns a module based on the module's unique name
         *
         * @param moduleName unique name of the module
         *
         * @return pointer to the module
         */
	Module *getModule(std::string moduleName);
        
        /**
         * Returns a list of all registered modules
         *
         * @return list of modules
         */
        const ModuleList *getModules();
        
        /**
         * Returns the associated FileManager
         *
         * @return the FileManager
         */
        FileManager *getFileManager();
        
    protected:
        
        /**
         * Initializes the module manager and the modules based on the input config descriptor.
         *
         * @param config configuration descriptor
         */
        void initialize(libconfig::Config* config);
        
        /**
         * Destroys the singleton instance.
         */
        static void destroyInstance();
        
        friend class Captool;
        
private:
    
        /**
         * Constructor.
         */
        ModuleManager();
        
        /**
         * Destructor.
         */
        ~ModuleManager();
        
        /**
         * Returns the ModuleLibrary handling the library with the given name.
         *
         * @param moduleLibraryName the name of the library
         *
         * @return pointer to the ModuleLibrary
         */
        ModuleLibrary* getModuleLibrary(std::string moduleLibraryName);

        /** to prevent copying */
	ModuleManager(const ModuleManager&);
        
        /** to prevent copying */
	ModuleManager& operator= (const ModuleManager&);

        /** the associated FileManager */
        FileManager  _fileManager;
        
// libraries are not used in static mode
#ifndef CAPTOOL_STATIC_BUILD

        /** type for map of ModuleLibrary instance */
        typedef std::map<std::string, ModuleLibrary*> LibraryMap;

        /** map of ModuleLibrary instance */
	LibraryMap _libraries;
        
#endif
	
        /** list of module instances in their order in the config file */
	ModuleList _modulesList;

        /** type for map of module instances  */
        typedef std::map<std::string, Module *> ModuleMap;
        
        /** map of module instances */
        ModuleMap  _modulesMap;
        
        /** the module to be run */
        ActiveModule* _activeModule;

	/** singleton instance */
        static ModuleManager *_pInstance;
        
       /**
        * Start the thread for control commands.
        * @note This method never throws or exits since Captool may still run
        * very well without any runtime control. */
        void * controlThread ();
        
        /**
         * Factory for running controlThread on behalf of a ModuleManager.
         * @param manager instance of ModuleManager
         * @note This method is not thread safe but until ModuleManager 
         *       is singleton I don't care.
         */
        static void * create_thread (void * manager);
        
        /** Port number to listen for control commands on */
        unsigned port;
        
        /** I/O service object underlying controlSocket */
        boost::asio::io_service controlService;
        
        /** TCP socket for the control service */
        boost::asio::ip::tcp::acceptor controlSocket;

        /** The default port number at which Captool listens for control commands */
        static const unsigned DEFAULT_CONTROL_PORT = 44444;
        
        /** Maximum number of retries during socet creation */
        static const unsigned MAX_BIND_RETRY_COUNT = 10;
};

inline FileManager *
ModuleManager::getFileManager()
{
    return &_fileManager;
}

} // namespace captool

#endif // __MODULE_MANAGER_H__
