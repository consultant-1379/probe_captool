/*
 * Module.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>
#include <string>
#include <cstdlib>

#include "util/log.h"
#include "Module.h"

using std::string;

namespace captool
{

const string Module::DEFAULT_CONNECTION_NAME("default");
    
Module::Module(string name)
    : _name(name),
      _outDefault(0)
{
}

void
Module::initialize(libconfig::Config *config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINER("initializing (base module).")

    // configure default output
    libconfig::Setting& connectionSettings = config->lookup("captool.modules." + _name + ".connections");
    
    for (int i=0; i<connectionSettings.getLength(); ++i) {
        libconfig::Setting& connection = connectionSettings[i];
        
        if (connection.getType() != libconfig::Setting::TypeList)
        {
            CAPTOOL_MODULE_LOG_SEVERE(i << "th connection setting is not a list")
            exit(-1);
        }

        if (connection.getLength() != 2)
        {
            CAPTOOL_MODULE_LOG_SEVERE("list no. " << i << " does not have a length of 2")
            exit(-1);
        }

        // skip not default
        if (connection[0].getType() != libconfig::Setting::TypeString || Module::DEFAULT_CONNECTION_NAME.compare((const char *)connection[0]) != 0)
        {
            continue;
        }
        
        // check list
        if (connection[0].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("firt element in list no. " << i << " is not a number.")
            exit(-1);
        }
        
        if (connection[1].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("second element in list no. " << i << " is not a string.")
            exit(-1);
        }
        
        string moduleName = connection[1];
        _outDefault = ModuleManager::getInstance()->getModule(moduleName);
        if (_outDefault == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
            exit(-1);
        }
    }
}

void
Module::configure (const libconfig::Setting &)
{
    CAPTOOL_MODULE_LOG_WARNING ("module does not accept runtime configuration updates.");
}

Module*
Module::process(CaptoolPacket *)
{
    CAPTOOL_MODULE_LOG_FINEST("processing packet (base module).")
    return 0;
}

Module*
Module::process(const Flow *)
{
    CAPTOOL_MODULE_LOG_FINEST("processing flow (base module).")
    return 0;
}


void
Module::getStatus(std::ostream *s, u_long, u_int)
{
    assert(s != 0);
    
    *s << "OK";
}

void
Module::fixHeader(CaptoolPacket *) {
    CAPTOOL_MODULE_LOG_FINE("fixing header (base module).")
}

void
Module::describe(const CaptoolPacket *, std::ostream *)
{
    CAPTOOL_MODULE_LOG_FINEST("describing packet (base module).")
}

int
Module::getDatalinkType() {
    return DLT_EN10MB;
}

} // namespace captool
