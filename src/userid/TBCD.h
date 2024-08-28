/*
 * TBCD.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __TBCD_H__
#define __TBCD_H__

#include <boost/shared_ptr.hpp>
#include <tr1/functional> // std::hash
#include <string>
#include "ID.h"

/**
 * Represent a TBCD encoded idenitification number (e.g., IMSI, IMEI(SV)).
 *
 * @author Gábor Németh <gabor.a.nemeth@ericsson.com>
 */
class TBCD : public ID {
    
    public:
        
        typedef boost::shared_ptr<TBCD> Ptr;
        
        /**
         * Construct ID from a raw TBCD string.
         * @note It is assumed that the supplied array is at least #TBCD_STRING_LENGTH long.
         */
        TBCD (uint8_t* const&);
        
        virtual ~TBCD ();
        
        /** length of an TBCD encoded representation */
        static const unsigned TBCD_STRING_LENGTH = 8;
        
    protected:
        /**
         * Generate ASCII transcript of the TBCD encoded ID.
         */
        void mkstring();
        
        /** unused value in TBCD representation */
        static const uint8_t TBCD_UNUSED = 0x0f;
};

std::ostream& operator<<(std::ostream&, const TBCD::Ptr&);

bool operator== (const TBCD::Ptr&, const TBCD::Ptr&);
bool operator!= (const TBCD::Ptr&, const TBCD::Ptr&);

namespace std { namespace tr1 {
    template<> std::size_t hash<TBCD::Ptr>::operator() (TBCD::Ptr) const;
}}

#endif
