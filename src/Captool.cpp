/*
 * Captool.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <exception>
#include <cstdlib>
#include <csignal>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string>

#include <ctime>

#ifdef CAPTOOL_PROFILE_PERFTOOLS
#include <google/heap-profiler.h>
#include <google/profiler.h>
#endif

#include "captoolpacket/CaptoolPacket.h"
#include "classification/ClassificationMetadata.h"
#include "modulemanager/ModuleManager.h"
#include "util/log.h"

#include "Captool.h"

using std::string;

using libconfig::Config;
using libconfig::Setting;
using libconfig::FileIOException;
using libconfig::ParseException;
using libconfig::SettingNotFoundException;

namespace captool
{

const string Captool::CONFIG_FILE = string("conf/captool.cfg");

Captool* Captool::_instance = 0;

Captool*
Captool::getInstance()
{
    if (_instance == 0)
    {
        _instance = new Captool();
    }
    
    assert(_instance != 0);
    
    return _instance;
}

void
Captool::destroyInstance()
{
    _instance->time(ModuleManager::getInstance()->getActiveModule()->getTime());
    delete(_instance);
    _instance = 0;
}

Captool::Captool()
    : ActiveModuleListener(),
    procfile(),
    _doStatusLog(false),
    _timerPeriod(30)
{
    pid_t pid = getpid();
    std::ostringstream oss;
    oss << "/proc/" << pid << "/statm";
    procfile.open(oss.str().c_str());
}

void
Captool::initialize()
{
    /* Open configuration */
    
    CAPTOOL_LOG_CONFIG("Captool loading config file \"" << CONFIG_FILE << "\".")
    
    // loading config file
    try {
        _config.readFile(CONFIG_FILE.c_str());
    } catch (FileIOException) {
        CAPTOOL_LOG_SEVERE("Captool error reading config file.")
        exit(-1);
    } catch (ParseException e) {
        CAPTOOL_LOG_SEVERE("Captool error parsing config file (" << e.getError() << " in line " << e.getLine() << ").")
        exit(-1);
    }

    // Initialize classification metadata
    ClassificationMetadata::getInstance().initialize(&_config);

    /* Initialize modules via ModuleManager*/
    CAPTOOL_LOG_FINE("Captool initializing modules.");
    try {
        ModuleManager *moduleManager = ModuleManager::getInstance();
        assert(moduleManager != 0);
        moduleManager->initialize(&_config);
    } catch (SettingNotFoundException) {
        CAPTOOL_LOG_SEVERE("Captool setting not found.")
        exit(-1);
    }

    
    // get status log file prefix
    if (!_config.lookupValue("captool.statusManager.filePrefix", _statusLogFilePrefix))
    {
        CAPTOOL_LOG_WARNING("StatusManager filePrefix not set. Status log disabled.")
    }
    else
    {
        // get status log file postfix
        if (!_config.lookupValue("captool.statusManager.filePostfix", _statusLogFilePostfix))
        {
            CAPTOOL_LOG_WARNING("StatusManager filePostfix not set. Status log disabled.")
        }
        else
        {
            _doStatusLog = true;
            openNewFiles();
        }
    }

    // set status log period
    if (!_config.lookupValue("captool.timerPeriod", _timerPeriod))
    {
        CAPTOOL_LOG_CONFIG("timer period not set, using default value (" << _timerPeriod << ").")
    }
    
    if (_timerPeriod == 0)
    {
        _doStatusLog = false;
    }

    if (_doStatusLog)
    {
        ModuleManager::getInstance()->getFileManager()->registerFileGenerator(this);    
    }
}

void
Captool::start()
{
    assert(ModuleManager::getInstance()->getActiveModule() != 0);

    if (_doStatusLog)
    {
        ModuleManager::getInstance()->getActiveModule()->setPeriod(_timerPeriod);
        ModuleManager::getInstance()->getActiveModule()->addListener(this);
        ModuleManager::getInstance()->getActiveModule()->addListener(ModuleManager::getInstance()->getFileManager());
    }
    
    ModuleManager::getInstance()->getActiveModule()->start();
}


void
Captool::stop()
{
    // interrupt might happen before configuration is completed
    if (ModuleManager::getInstance()->getActiveModule() == 0)
    {
        CAPTOOL_LOG_FINE("Captool destroying Captool instance")
        captool::Captool::destroyInstance();
    }
    else
    {
        CAPTOOL_LOG_INFO("Captool stopping Active module.")
        ModuleManager::getInstance()->getActiveModule()->stop();
    }
}

void
Captool::time(const struct timeval *time)
{
    static struct timeval startTime = *time;
    u_long runtime = time->tv_sec - startTime.tv_sec;
    static u_long lasttime = runtime; // ugly;  relies on singletonity of Captool
    u_long period = runtime - lasttime;
    
    u_int seconds = runtime % 60;
    u_int minutes = (runtime / 60) % 60;
    u_long hours = runtime / 3600;
    
    CAPTOOL_LOG_INFO("Captool runtime: " << hours << "h " << minutes << "m " << seconds << "s");
    
    _statusLogFileStream << "Status at runtime: " << hours << "h " << minutes << "m " << seconds << "s\n";
    long page = sysconf(_SC_PAGESIZE);
    long unsigned sz, res, sh, txt, dummy, data;
    procfile.seekg(0) >> sz >> res >> sh >> txt >> dummy >> data >> dummy;
    _statusLogFileStream << "Memory usage:  total " << (unsigned)(sz * page / 1e6) << "MiB, resident " << (unsigned)(res * page / 1e6) << "MiB, data+stack " << (unsigned)(data * page / 1e6) << "MiB\n";

    const ModuleManager::ModuleList *modules = ModuleManager::getInstance()->getModules();

    for (ModuleManager::ModuleList::const_iterator iter(modules->begin()), end(modules->end()); iter != end; ++iter)
    {
        _statusLogFileStream << *(*iter)->getName() << ": ";
        (*iter)->getStatus(&_statusLogFileStream, runtime, period);
        _statusLogFileStream << "\n";
    }

    _statusLogFileStream << "\n";
    
    lasttime = runtime;
}

void
Captool::openNewFiles()
{
    ModuleManager::getInstance()->getFileManager()->openNewFile(_statusLogFileStream, _statusLogFilePrefix, _statusLogFilePostfix);
}

Captool::~Captool()
{
    CAPTOOL_LOG_FINER("Captool destroying ModuleManager and ClassificationMetadata singleton instances.")
    ModuleManager::destroyInstance();
    ClassificationMetadata::getInstance().destroyInstance();
}

} // namespace captool








void interrupted (int)
{
    CAPTOOL_LOG_WARNING("Captool interrupted.")

    // ignore further interrupts;
    signal(SIGINT, SIG_IGN);
            
    //stop the active module
    captool::Captool::getInstance()->stop();
}

int main (int, char * [])
{
    // register interrupt function
    signal(SIGINT, interrupted);

    // desync ios base from cstdlib
    std::ios_base::sync_with_stdio(false);
    
#ifdef CAPTOOL_PROFILE_PERFTOOLS
    //HeapProfilerStart("captool-heap-prof");
    ProfilerStart("captool-prof");
#endif
    
    try
    {
    
        // get captool instance and initialize
        captool::Captool* captool = captool::Captool::getInstance();

        assert(captool != 0);
    
        captool->initialize();

        // start active module and wait till it finishes
        captool->start();

        CAPTOOL_LOG_FINE("Captool destroying Captool instance")
        captool::Captool::destroyInstance();

    }
    catch (const std::exception &e)
    {
        CAPTOOL_LOG_SEVERE("Captool caught exception: " << e.what())
    }
    catch (...)
    {
        CAPTOOL_LOG_SEVERE("Captool caught an unknown exception.")
    }
    
#ifdef CAPTOOL_PROFILE_PERFTOOLS
    ProfilerStop();
    //HeapProfilerStop();
#endif
    
    return 0;
}
