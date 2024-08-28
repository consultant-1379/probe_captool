/*
 * ParametersContainer.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PARAMETERS_CONTAINER_H__
#define __PARAMETERS_CONTAINER_H__

#include <string>
#include <map>

using std::string;
using std::map;
using std::pair;

/** Empty superclass of parameters to be stored */
class Parameter
{
    public:

        /** Constructor */
        Parameter();

        /** Destructor */
        virtual ~Parameter();
};

inline
Parameter::Parameter()
{
}

inline
Parameter::~Parameter()
{
}

/** Allows binding arbitrary data structures to strings (simple hash table wrapper) */
class ParametersContainer
{
    public:

        /** Constructor */
        ParametersContainer();

        /** Destructor */
        virtual ~ParametersContainer();

        /**
         * Registers a new name/value pair. If a value is already registered,
         * than the does nothing.
         *
         * @param name the name of the parameter to be registered
         * @param value pointer to the value of the parameter to be registered
         *
         * @return true if the new parameter has been successfully registered and false if it had already been registered previously
         */
        bool setParameter(string name, Parameter* value);

        /**
         * Get the value of the parameter registered for the given name
         *
         * @param name the name of the parameter whose value is to be retrieved.
         * @return a pointer to the value associated to the given name or NULL if no parameters are registered for the given name.
         */
        Parameter* getParameter(string name);

    private:

        /** Map storing parameter name <-> parameter value pairs */
        std::map<string,Parameter*> _parameters;
};

inline
ParametersContainer::ParametersContainer()
{
}

inline
ParametersContainer::~ParametersContainer()
{
    for (map<string,Parameter*>::const_iterator it = _parameters.begin(); it != _parameters.end(); ++it)
    {
        delete (it->second);
    }
}

inline
bool
ParametersContainer::setParameter(string name, Parameter* value)
{
    pair<map<string,Parameter*>::iterator,bool> ret = _parameters.insert(std::make_pair(name, value));
    return ret.second;
}

inline
Parameter*
ParametersContainer::getParameter(string name)
{
    map<string,Parameter*>::iterator it = _parameters.find(name);
    return it == _parameters.end() ? NULL : it->second;
}

#endif /* __PARAMETERS_CONTAINER_H__ */
