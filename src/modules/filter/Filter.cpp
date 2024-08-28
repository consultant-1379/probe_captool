/*
 * Filter.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include <iostream>
#include <sstream>

#include <netinet/in.h>

#include "modulemanager/ModuleManager.h"

#include "Filter.h"

#include "PortFilterProcessor.h"
#include "IPRangeFilterProcessor.h"
#include "SamplingFilterProcessor.h"
#include "TacFilterProcessor.h"
#include "UserFilterProcessor.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(Filter)

const string Filter::PASS_CONNECTION_NAME("pass");
const string Filter::DROP_CONNECTION_NAME("drop");

const string Filter::FILTERING_FILTER_MODE("filtering");
const string Filter::SAMPLING_FILTER_MODE("sampling");

const string Filter::IMSI_FILTER_TYPE("imsi");
const string Filter::TAC_FILTER_TYPE("tac");
const string Filter::IP_FILTER_TYPE("ip");
const string Filter::PORT_FILTER_TYPE("port");

Filter::Filter(string name)
    : Module(name),
      _outPass(0),
      _outDrop(0),
      _allPackets(0),
      _passedPackets(0),
      _bypass(false),
      _invert(false)
            
{
}

Filter::~Filter()
{
}

void
Filter::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    string mygroup = "captool.modules." + _name;

    /* configure connections */

    libconfig::Setting& connectionSettings = config->lookup(mygroup + ".connections");
    
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

        // skip default
        if (connection[0].getType() == libconfig::Setting::TypeString && Module::DEFAULT_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            continue;
        }
        
        // check list
        if (connection[0].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("first element in list no. " << i << " is not a string.")
            exit(-1);
        }
        
        if (connection[1].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("second element in list no. " << i << " is not a string.")
            exit(-1);
        }
        
        if (Filter::PASS_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outPass = ModuleManager::getInstance()->getModule(moduleName);
            if (_outPass == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (Filter::DROP_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outDrop = ModuleManager::getInstance()->getModule(moduleName);
            if (_outDrop == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        CAPTOOL_MODULE_LOG_SEVERE("connection name must be pass or drop (or default)");
        exit(-1);
    }
    
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));

    if (_filterProcessor == NULL)
    {
        exit(-1);
    }
}

void
Filter::configure (const libconfig::Setting & config)
{
    if (!config.lookupValue("bypass", _bypass))
    {
        _bypass = false;
    }
    CAPTOOL_MODULE_LOG_CONFIG("Bypass property set to " << (_bypass ? "true" : "false (default)"))
    if (!config.lookupValue("invert", _invert))
    {
        _invert = false;
    }
    CAPTOOL_MODULE_LOG_CONFIG("Invert property set to " << (_invert ? "true" : "false (default)"))

    FilterProcessor * filterProcessor = createFilterProcessor(config);
    if (filterProcessor != NULL)
    {
        // TBD: delete previous filter processor (needs to be synchronized!)
        _filterProcessor = filterProcessor;
    }
}

FilterProcessor *
Filter::createFilterProcessor(const libconfig::Setting& config)
{
    // Read filter mode (sampling | filtering)
    string mode;
    if (!config.lookupValue("mode", mode))
    {
        CAPTOOL_MODULE_LOG_SEVERE("Mode parameter not set for filter! Please specify either \"" << SAMPLING_FILTER_MODE << "\" or \"" << FILTERING_FILTER_MODE << "\"")
        return NULL;
    }
    CAPTOOL_MODULE_LOG_CONFIG("Filter mode set to " << mode)

    // Read filter type (imsi | tac | ip | port)
    string type;
    if (!config.lookupValue("filtertype", type))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filtertype parameter not set for filter!")
        return NULL;
    }
    CAPTOOL_MODULE_LOG_CONFIG("Filter type set to " << type)

    if (mode == "sampling")
    {
        if (type == IMSI_FILTER_TYPE)
        {
            double ratio;
            if (!config.lookupValue("ratio", ratio))
            {
                CAPTOOL_MODULE_LOG_SEVERE("Ratio parameter not set for sampling filter!")
                return NULL;
            }
            CAPTOOL_MODULE_LOG_CONFIG("Sampling ratio set to " << ratio)
            return new SamplingFilterProcessor(SamplingFilterProcessor::IMSI, ratio);
        }
        else
        {
            CAPTOOL_MODULE_LOG_SEVERE("Sampling filter mode is currently supported only for filter type \"" << IMSI_FILTER_TYPE << "\"")
            return NULL;
        }
    }
    else if (mode == "filtering")
    {
        // Read values for which the filter should return "pass"
        libconfig::Setting& values = config["values"];
        if (!values.isArray())
        {
            CAPTOOL_MODULE_LOG_SEVERE("Filter values are not specified as an array")
            return NULL;
        }
        // Set of integer elements for which the filter should return "pass"
        set<int>        intValues;
        // Set of integer elements for which the filter should return "pass"
        set<string>     stringValues;
        
        for (int i=0; i<values.getLength(); i++)
        {
            if (type == PORT_FILTER_TYPE)
            {
                int port = values[i];
                if (port > 65535 || port < 0)
                {
                    CAPTOOL_MODULE_LOG_SEVERE("Invalid port number specified in filter: " << port)
                    return NULL;
                }
                CAPTOOL_MODULE_LOG_CONFIG("Added " << port << " to filter values")
                intValues.insert(htons((u_int16_t)port));
            }
            else
            {
                string value = values[i];
                stringValues.insert(value);
                CAPTOOL_MODULE_LOG_CONFIG("Added " << value << " to filter values")
            }
        }

        if (type == IMSI_FILTER_TYPE)
        {
            return new UserFilterProcessor(stringValues);
        }
        else if (type == TAC_FILTER_TYPE)
        {
            return new TacFilterProcessor(stringValues);
        }
        else if (type == PORT_FILTER_TYPE)
        {
            string tmp;
            PortFilterProcessor::TransportType transport = PortFilterProcessor::ANY;
            if (config.lookupValue("transport", tmp))
            {
                if (tmp == "udp" || tmp == "UDP")
                {
                    transport = PortFilterProcessor::UDP;
                }
                else if (tmp == "tcp" || tmp == "TCP")
                {
                    transport = PortFilterProcessor::TCP;
                }
                else
                {
                    CAPTOOL_MODULE_LOG_SEVERE("Invalid transport type specified for port filter: " << tmp)
                    return NULL;
                }
                CAPTOOL_MODULE_LOG_CONFIG("Transport type set to " << tmp)
            }
            else
            {
                CAPTOOL_MODULE_LOG_CONFIG("Transport type set to none (default)")
            }

            PortFilterProcessor::EndpointType endpoint;
            if (!config.lookupValue("endpoint", tmp))
            {
                CAPTOOL_MODULE_LOG_SEVERE("No endpoint type specified for port filter!")
                return NULL;
            }
            else
            {
                if (tmp == "subscriber")
                {
                    endpoint = PortFilterProcessor::SUBSCRIBER;
                }
                else if (tmp == "peer")
                {
                    endpoint = PortFilterProcessor::PEER;
                }
                else
                {
                    CAPTOOL_MODULE_LOG_SEVERE("Invalid endpoint type specified for port filter: " << tmp)
                    return NULL;
                }
                CAPTOOL_MODULE_LOG_CONFIG("Endpoint type set to " << tmp)
            }
            return new PortFilterProcessor(transport, endpoint, intValues);
        }
        else if (type == IP_FILTER_TYPE)
        {
            IPRangeFilterProcessor::EndpointType endpoint;
            string tmp;
            if (!config.lookupValue("endpoint", tmp))
            {
                CAPTOOL_MODULE_LOG_SEVERE("No endpoint type specified for IP range filter!")
                return NULL;
            }
            else
            {
                if (tmp == "subscriber")
                {
                    endpoint = IPRangeFilterProcessor::SUBSCRIBER;
                }
                else if (tmp == "peer")
                {
                    endpoint = IPRangeFilterProcessor::PEER;
                }
                else
                {
                    CAPTOOL_MODULE_LOG_SEVERE("Invalid endpoint type specified for IP range filter: " << tmp)
                    return NULL;
                }
                CAPTOOL_MODULE_LOG_CONFIG("Endpoint type set to " << tmp)
            }

            return new IPRangeFilterProcessor(endpoint, stringValues);
        }
        else
        {
            CAPTOOL_MODULE_LOG_SEVERE("Invalid type parameter: " << mode)
            return NULL;
        }
    }
    else
    {
        CAPTOOL_MODULE_LOG_SEVERE("Invalid mode parameter: " << mode << ". Please specify either \"" << SAMPLING_FILTER_MODE << "\" or \"" << FILTERING_FILTER_MODE << "\"")
        return NULL;
    }
}

Module*
Filter::process(CaptoolPacket* packet)
{
    if (_bypass) return _outPass;

    assert(packet != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    _allPackets++;

    Flow * flow = packet->getFlow().get();

    if ( (!_invert && _filterProcessor->test(packet, flow)) || (_invert && !_filterProcessor->test(packet, flow)) ) {
        _passedPackets++;
        return _outPass;
    }
    
    return _outDrop;
}

void
Filter::getStatus(std::ostream *s, u_long, u_int)
{
    if (_bypass)
    {
        *s << "filter disabled (bypass mode)";
    }
    else
    {
        *s << "passing " << _passedPackets << "/" << _allPackets << " packets.";
    }
}

