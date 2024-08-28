/*
 * OptionsContainer.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __OPTIONS_CONTAINER_H__
#define __OPTIONS_CONTAINER_H__

#include <ostream>

#include <string>
#include <map>

/**
 * Stores name - value option fields.
 */
class OptionsContainer
{
    protected:
        
        /** 
         * Separator between multiple values of the same flow option
         * @see registerOption()
         */
        static std::string      OPTION_SEPARATOR;
        
    public:
        
        /**
         * Constructor.
         */
        OptionsContainer();
        
        /**
         * Destructor.
        */
        virtual ~OptionsContainer();
        
        /**
         * Print optional flow parameters in key=value format
         */
        void printOptions(std::ostream *s) const;
        
        /**
         * Set/append value to a flow option
         * @param optionName name of the option we are updating
         * @param optionValue new or appended value
         * @param append append to the previous value of the option
         * @param appendSame when appending, append the value even if is already there
         * @param sep separator when appending multiple values
         */
        void registerOption(std::string optionName, std::string optionValue, bool append = false, bool appendSame = false, const std::string sep = OPTION_SEPARATOR);
        
        /**
         * Retreive flow option
         *
         * @return the value of the given option or null if such option has not yet been registered
         */
        std::string getOption(std::string optionName) const;
        
        /**
         * Test wether a specific option has already been set for this flow
         *
         * @return true if this option has already been registered; false otherwise
         */
        bool testOption(std::string optionName) const;
        
    protected:
        
        /** Map to store options to be printed out */
        std::map<std::string, std::string> _optionMap;
};

inline
OptionsContainer::OptionsContainer()
{
}

inline
OptionsContainer::~OptionsContainer()
{
}

inline void
OptionsContainer::registerOption(std::string optionName, std::string optionValue, bool append, bool appendSame, const std::string separator)
{
    std::string & val = _optionMap[optionName];
    
    if (append)
    {
        if (val.empty())
            val = optionValue;
        else
            if (appendSame || val.find(optionValue) == std::string::npos)
                val.append(separator + optionValue);
    }
    else 
    {
        val = optionValue;
    }
}
    
inline std::string
OptionsContainer::getOption(std::string optionName) const
{
    std::map<std::string,std::string>::const_iterator i = _optionMap.find(optionName);
    return i == _optionMap.end() ? "" : i->second;
}
    
inline bool
OptionsContainer::testOption(std::string optionName) const
{
    return _optionMap.find(optionName) != _optionMap.end();
}

#endif // __OPTIONS_CONTAINER_H__
