/*
 * GTPInformationElements.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __GTP_INFORMATION_ELEMENTS_H__
#define __GTP_INFORMATION_ELEMENTS_H__

#include <sys/types.h>
#include <string>

class GTPControl;

/**
 * Helper class for storing information associated with GTP information elements.
 */
class GTPInformationElements
{
    public:

        /**
         * Constructor.
         */
        GTPInformationElements();
        
        /**
         * Destructor.
         */
        ~GTPInformationElements();
        
        /**
         * Returns whether the given information element type is valid.
         *
         * @param type the information element type
         *
         * @return true if the given information element type is valid
         */
        bool isValid(u_int8_t type) const;

        /**
         * Returns the name of the information element with the given type.
         *
         * @param type type of the information element
         *
         * @return a pointer to name of the information element
         */
        const std::string *getName(u_int8_t type) const;

        /**
         * Returns the length of the information element with the given type for TVs.
         *
         * @param type type of the information element
         *
         * @return the length of the information element, or 0 if unknown
         */
        u_int8_t getLength(u_int8_t type) const;

    private:

        /** array for storing validity of information elements */
        bool _validInformationElements[256];

        /** array for storing information element names */
        std::string _informationElementNames[256];
        
        /** array for storing TV information element lengths */
        u_int16_t _informationElementTVLengths[256];
        
};

inline bool
GTPInformationElements::isValid(u_int8_t type) const
{
    return _validInformationElements[type];
}


inline const std::string*
GTPInformationElements::getName(u_int8_t type) const
{
    return &_informationElementNames[type];
}

inline u_int8_t
GTPInformationElements::getLength(u_int8_t type) const
{
    return _informationElementTVLengths[type];
}

#endif // __GTP_INFORMATION_ELEMENTS_H__
