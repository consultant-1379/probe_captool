/*
 * IdNameMapper.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "IdNameMapper.h"

IdNameMapper::IdNameMapper() :
    lastId(0)
{
}

unsigned
IdNameMapper::registerName(string name)
{
    std::map<string,unsigned>::const_iterator it = nameIdMap.find(name);
    if (it == nameIdMap.end())
    {
        ++lastId;
        nameIdMap.insert(std::make_pair(name, lastId));
        idNameMap.insert(std::make_pair(lastId, name));
        return lastId;
    }
    else 
    {
        return it->second;
    }
}

unsigned
IdNameMapper::getId(string name) const
{
    std::map<string,unsigned>::const_iterator it = nameIdMap.find(name);
    return it == nameIdMap.end() ? unsigned(-1) : it->second;
}

string
IdNameMapper::getName(unsigned id) const
{
    std::map<unsigned,string>::const_iterator it = idNameMap.find(id);
    return it == idNameMap.end() ? "na" : it->second;
}

unsigned
IdNameMapper::size() const
{
    return lastId;
}