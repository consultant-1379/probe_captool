/*
 * IdNameMapper.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __ID_NAME_MAPPER__
#define __ID_NAME_MAPPER__

#include <map>
#include <string>

using std::string;

/**
 * Provides automatic and transparent mapping of strings to (unsigned int) IDs and vice versa.
 * Assignment of IDs starts at 1 and IDs are assigned incrementally,
 * hence the last ID equals to the total number of registered mappings.
 */
class IdNameMapper
{
    public:
        
        IdNameMapper();
        
        /**
         * If not yet registered, than assigns the given string to the next available ID;
         *
         * @param name the string to be registered
         * @return the ID assigned to the given string
         */
        unsigned registerName(const string name);
        
        /**
         * Returns the ID assigned to the given string or -1 if the given string has not been registered
         */
        unsigned getId(const string name) const;
        
        /**
         * Returns the string associated to the given ID or "na" if this ID has not yet been registered
         */
        string getName(unsigned id) const;
        
        /** Returns the ID of the last registered element, which is equal to the total number of registered elements */
        unsigned size() const;
        
    private:
    
        std::map<unsigned, string> idNameMap;
        std::map<string, unsigned> nameIdMap;
        
        unsigned lastId;
};

#endif // header file