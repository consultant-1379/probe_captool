/*
 * OptionsContainer.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "OptionsContainer.h"

std::string OptionsContainer::OPTION_SEPARATOR = "\t";

void
OptionsContainer::printOptions(std::ostream *s) const
{
    for (std::map<std::string,std::string>::const_iterator i = _optionMap.begin(); i != _optionMap.end(); ++i)
    {
        *s << "|" << i->first << "=" << i->second;
    }
}

