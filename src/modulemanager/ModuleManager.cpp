/*
 * ModuleManager.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>
#include <sys/socket.h>
#include <iostream>
#include <cstdlib>
#include <pthread.h>
#include <string>
#include <fstream> // FIXME for tempfile writing in controlThread()
#include <cstdio>  // this one too
#include <unistd.h> // and this one (unlink())

#include "util/log.h"
#include "NullModule.h"
#include "ModuleManager.h"

// if statically built, modules can be included
#ifdef CAPTOOL_STATIC_BUILD
#include "modules/eth/ETH.h"
#include "modules/eth/LinuxCookedHeader.h"
#include "modules/flowoutput/FlowOutput.h"
#include "modules/flowoutput/FlowOutputStrict.h"
#include "modules/flowpacket/FlowPacket.h"
#include "modules/gtpcontrol/GTPControl.h"
#include "modules/gtpuser/GTPUser.h"
#include "modules/ip/IP.h"
#include "modules/filter/Filter.h"
#include "modules/pcapcapture/PcapCapture.h"
#include "modules/pcapoutput/PcapOutput.h"
#include "modules/summary/Summarizer.h"
#include "modules/tcp/TCP.h"
#include "modules/udp/UDP.h"
#include "modules/http/HTTP.h"
#include "modules/classifiers/DPI.h"
#include "modules/classifiers/PortClassifier.h"
#include "modules/classifiers/IPRangeClassifier.h"
#include "modules/classifiers/IPTransportClassifier.h"
#include "modules/classifiers/SequenceNumberClassifier.h"
#include "modules/classifiers/ClassifierDispatcher.h"
#include "modules/classifiers/ClassAssigner.h"
#include "modules/classifiers/ServerPortSearch.h"
#include "modules/classifiers/P2PHostSearch.h"
#include "flowmodules/P2PHeuristics.h"
#endif

using std::string;
using std::pair;

namespace captool
{

ModuleManager* ModuleManager::_pInstance = 0;

ModuleManager::ModuleManager()
    : port (DEFAULT_CONTROL_PORT),
      controlService (),
      controlSocket (controlService)
{
}

ModuleManager*
ModuleManager::getInstance()
{
    if (_pInstance == 0)
    {
	_pInstance = new ModuleManager();
    }
    
    return _pInstance;
}

void
ModuleManager::destroyInstance()
{
    if (_pInstance != 0)
    {
        delete(_pInstance);
        _pInstance = 0;
    }
}

void
ModuleManager::initialize(libconfig::Config* config)
{
    assert(config != 0);

    /* Create modules */
    
    // initialize null module
    Module * nullModule = new NullModule("null");
    _modulesMap.insert(std::pair<string, Module*>("null", nullModule));
    
    // get list of modules
    libconfig::Setting& modulesSetting = config->lookup("captool.modules");
    
    // iterate over modules
    for (int i=0; i<modulesSetting.getLength(); ++i) {

        // initialize each module
        libconfig::Setting& moduleSetting = modulesSetting[i];
        string moduleName(moduleSetting.getName());
        
        if (getModule(moduleName) != 0)
        {
            CAPTOOL_LOG_SEVERE("ModuleManager duplicate module name: " << moduleName)
            exit(-1);
        }
        
        string moduleLibraryName = moduleSetting["type"];
        
        CAPTOOL_LOG_FINE("ModuleManager creating module " << moduleName << ", type " << moduleLibraryName << ".")

        Module* module = 0;

// load libraries        
#ifndef  CAPTOOL_STATIC_BUILD
        // get library
        ModuleLibrary* library = getModuleLibrary(moduleLibraryName);
        
        // create module
        module = library->createInstance(moduleName);
// or simply create new instance if statically built
#else
             if (moduleLibraryName == "ETH")         module = new ETH(moduleName);
        else if (moduleLibraryName == "LinuxCookedHeader")  module = new LinuxCookedHeader(moduleName);
        else if (moduleLibraryName == "FlowOutput")  module = new FlowOutput(moduleName);
        else if (moduleLibraryName == "FlowOutputStrict")  module = new FlowOutputStrict(moduleName);
        else if (moduleLibraryName == "FlowPacket")  module = new FlowPacket(moduleName);
        else if (moduleLibraryName == "GTPControl")  module = new GTPControl(moduleName);
        else if (moduleLibraryName == "GTPUser")     module = new GTPUser(moduleName);
        else if (moduleLibraryName == "HTTP")          module = new HTTP(moduleName);
        else if (moduleLibraryName == "IP")          module = new IP(moduleName);
        else if (moduleLibraryName == "Filter")  module = new Filter(moduleName);
        else if (moduleLibraryName == "PcapCapture") module = new PcapCapture(moduleName);
        else if (moduleLibraryName == "PcapOutput")  module = new PcapOutput(moduleName);
        else if (moduleLibraryName == "Summarizer")  module = new Summarizer(moduleName);
        else if (moduleLibraryName == "TCP")         module = new TCP(moduleName);
        else if (moduleLibraryName == "UDP")         module = new UDP(moduleName);
        else if (moduleLibraryName == "DPI")         module = new DPI(moduleName);
        else if (moduleLibraryName == "ClassifierDispatcher")         module = new ClassifierDispatcher(moduleName);
        else if (moduleLibraryName == "ClassAssigner")         module = new ClassAssigner(moduleName);
        else if (moduleLibraryName == "PortClassifier")         module = new PortClassifier(moduleName);
        else if (moduleLibraryName == "IPRangeClassifier")         module = new IPRangeClassifier(moduleName);
        else if (moduleLibraryName == "IPTransportClassifier")         module = new IPTransportClassifier(moduleName);
        else if (moduleLibraryName == "SequenceNumberClassifier")         module = new SequenceNumberClassifier(moduleName);
        else if (moduleLibraryName == "ServerPortSearch")         module = new ServerPortSearch(moduleName);
        else if (moduleLibraryName == "P2PHostSearch")         module = new P2PHostSearch(moduleName);
        else if (moduleLibraryName == "P2PHeuristics")         module = new P2PHeuristics(moduleName);
        else {
            CAPTOOL_LOG_SEVERE("ModuleManager no such module: " << moduleLibraryName)
            exit(-1);
        }
#endif // CAPTOOL_STATIC_BUILD

        // save module
        _modulesList.push_back(module);
        _modulesMap.insert(std::pair<string, Module*>(moduleName, module));
    }
    
    /* Initialize FileManager */
    
    _fileManager.initialize(config);
    
    /* Initialize all modules after all modules were created */
    for (ModuleList::const_iterator iter(_modulesList.begin()), end(_modulesList.end()); iter != end; ++iter)
    {
        assert((*iter) != 0);
        
        (*iter)->initialize(config);
    }

    /* Get active module from configuration, and module manager*/
    string activeModuleName = "";
    
    if (!config->lookupValue("captool.moduleManager.activeModule", activeModuleName))
    {
	CAPTOOL_LOG_SEVERE("Captool active module not set. Nothing to run.")
	exit(-1);
    }
    
    _activeModule = (ActiveModule *)ModuleManager::getInstance()->getModule(activeModuleName);
    
    if (_activeModule == 0)
    {
        CAPTOOL_LOG_SEVERE("Captool active module not found.")
        exit(-1);
    }
    
    /* Fire up command listener thread */
    if (!config->lookupValue("captool.controlPort", port))
    {
        CAPTOOL_LOG_CONFIG("Control port not set, using default port " << port)
    }
    
    if (port)
    {
        try
        {
            using boost::asio::ip::tcp;
            
            bool done = false;
            for (unsigned retry = 0; retry < MAX_BIND_RETRY_COUNT; ++retry)
            {
                try
                {
                    tcp::endpoint endpoint(tcp::v4(), port);
                    controlSocket.open(endpoint.protocol());
                    controlSocket.set_option(tcp::acceptor::reuse_address(true));
                    controlSocket.bind(endpoint);
                    done = true;
                    break;
                }
                catch (boost::system::system_error)
                {
                    try
                    {
                        controlSocket.close();
                    }
                    catch (boost::system::system_error) {}
                    ++ port;
                }
            }
            
            if (! done)
                throw std::runtime_error("could not bind port");
            
            controlSocket.listen(1);
        }
        catch (std::exception & e)
        {
            CAPTOOL_LOG_SEVERE("Problem opening control socket: " << e.what());
            exit(-1);
        }

        CAPTOOL_LOG_CONFIG("Listening for control commands at port " << port);

        pthread_t thread;
        int result = pthread_create(&thread, NULL, create_thread, reinterpret_cast<void*>(this));
        if (result < 0)
        {
            CAPTOOL_LOG_SEVERE("Problem starting control thread: " << strerror(errno));
            exit(-1);
        }
    }
}

ActiveModule *
ModuleManager::getActiveModule()
{
    return _activeModule;
}

ModuleLibrary*
ModuleManager::getModuleLibrary(string moduleLibraryName)
{
#ifndef CAPTOOL_STATIC_BUILD
    // lookup library to see if already loaded
    LibraryMap::const_iterator iter = _libraries.find(moduleLibraryName);
    
    if (iter == _libraries.end())
    {
        // load and store library if it was not loaded
        ModuleLibrary* library = new ModuleLibrary(moduleLibraryName);
        _libraries[moduleLibraryName] = library;

        assert(library != 0);
        return library;
    }
    else
    {
        assert((iter->second) != 0);
        return (ModuleLibrary*)(iter->second);
    }
#else    
    return 0;
#endif // CAPTOOL_STATIC_BUILD
    
}

Module*
ModuleManager::getModule(string moduleName)
{
    ModuleMap::const_iterator iter = _modulesMap.find(moduleName);
    
    if (iter == _modulesMap.end())
    {
        return 0;
    }
    else
    {
        return (Module *)iter->second;
    }
}

const ModuleManager::ModuleList *
ModuleManager::getModules()
{
    return &_modulesList;
}

ModuleManager::~ModuleManager()
{
    // delete modules
    for (ModuleMap::const_iterator iter(_modulesMap.begin()), end(_modulesMap.end()); iter != end; ++iter)
    {
        delete ((Module *)iter->second);
    }

#ifndef CAPTOOL_STATIC_BUILD
    // delete libraries
    for (LibraryMap::const_iterator it(_libraries.begin()), end(_libraries.end()); it != end; ++it)
    {
        delete((ModuleLibrary*)it->second);
    }
#endif
}

void *
ModuleManager::controlThread()
{
    while (true)
    {
        try
        {
            using boost::asio::ip::tcp;
            
            std::string input;
            try
            {
                tcp::iostream stream;
                controlSocket.accept(*stream.rdbuf());
                CAPTOOL_LOG_FINE("Accepted control connection");
                while (stream.good()) {
                    std::string line;
                    getline(stream, line);
                    if (line.length())
                        input += line + "\n";
                }
            }
            catch (boost::system::system_error & e)
            {
                CAPTOOL_LOG_WARNING("Problem accepting on control socket: " << e.what() << ";  try again.");
                continue;
            }
            
            CAPTOOL_LOG_FINE("Received command:\n" << input);
            
            libconfig::Config cfg;
            char fname [L_tmpnam];
            
            try
            {
                // cfg.readString(input); // FIXME hehehe would be to easy but only supported by libconfig++ 1.4.x, not 1.3.x which is in Debian/Ubuntu currently
                
                tmpnam(fname);
//                CAPTOOL_LOG_WARNING("temp file name: " << fname);
                std::ofstream os;
                os.open(fname);
                os << input;
                os.close();
                FILE * f = fopen(fname, "r");
                if (f) {
                    cfg.read(f);
                    fclose(f);
                }
            }
            catch (libconfig::ParseException & e)
            {
                CAPTOOL_LOG_WARNING("Invalid configuration on control socket: " << e.getError() << " on input line " << e.getLine() << "\n" << input)
                continue;
            }
            
            unlink(fname);
            
            try
            {
                const libconfig::Setting & root = cfg.getRoot();
                for (int i = 0; i < root.getLength(); ++i)
                {
                    const libconfig::Setting & s = root[i];
                    const std::string name = s.getName();
                    if (s.isGroup())
                    {
                        Module * module = getModule(name);
                        if (module)
                        {
                            module->configure(s);
                        }
                        else if (name == "fileManager") // FIXME big fat hack;  not only modules are Configurable so probably this function is at the wrong place here
                        {
                            ModuleManager::getInstance()->getFileManager()->configure(s);
                        }
                        else
                        {
                            CAPTOOL_LOG_WARNING("Runtime configuration: no such module: " << name << ";  skipping.")
                        }
                    }
                    else
                    {
                        CAPTOOL_LOG_WARNING("Invalid configuration: " << name << " is not a group on line " << s.getSourceLine() << ";  skipping.")
                    }
                }
            }
            catch (libconfig::ConfigException & e)
            {
                CAPTOOL_LOG_SEVERE("Exception during configuration processing: " << e.what() << ";  try again.")
            }
        }
        catch (...)
        {
            CAPTOOL_LOG_SEVERE("Unhandled exception in control thread;  try again.")
        }
    }
    
    return NULL;
}

void *
ModuleManager::create_thread (void * manager)
{
    ModuleManager * m = reinterpret_cast<ModuleManager*>(manager);
    return m->controlThread();
}

} // namespace captool
