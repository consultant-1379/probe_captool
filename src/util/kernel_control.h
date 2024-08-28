/*
 * kernel_control.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CAPTOOL_KERNEL_CONTROL_H__
#define __CAPTOOL_KERNEL_CONTROL_H__

#include <fstream>
#include <string>
#include <sstream>
#include "ip/IPAddress.h"

static const char * CAPTOOL_MODULE_CONTROL_FNAME = "/proc/net/captool_filter_control";

/**
 * Send control command to Captool kernel module.
 *
 * Accepted commands are:
 *   - "set 10.23.22.3"     # add IP address to filter table
 *   - "clear 10.23.11.4"   # remove address from filter table
 *   - "clear all"          # remove all addresses
 *   - "mode block"         # IP addresses in the table will be blocked
 *   - "mode accept"        # IP addresses will be accepted
 *
 * @param cmd single line of control command
 * @return true if successfully written to control file (does not mean it was properly processed though!)
 */
bool captool_module_control (const char* cmd)
{
    std::ofstream ctrl (CAPTOOL_MODULE_CONTROL_FNAME, std::ios_base::out | std::ios_base::app);
    if (! ctrl.fail())
        ctrl << cmd << std::endl;
    ctrl.close();
    return ! ctrl.fail();
}

bool captool_module_control (const std::string & cmd)
{
    return captool_module_control(cmd.c_str());
}

bool captool_module_add_ip (const IPAddress & ip)
{
    std::ostringstream ss;
    ss << "set " << IPAddress(ip.getRawAddress(), false);
    return captool_module_control(ss.str());
}

bool captool_module_add_ip (const IPAddress::Ptr & ip)
{
    return captool_module_add_ip(*(ip.get()));
}

bool captool_module_remove_ip (const IPAddress & ip)
{
    std::ostringstream ss;
    ss << "clear " << IPAddress(ip.getRawAddress(), false);
    return captool_module_control(ss.str());
}

bool captool_module_remove_ip (const IPAddress::Ptr & ip)
{
    return captool_module_remove_ip(*(ip.get()));
}

#endif
