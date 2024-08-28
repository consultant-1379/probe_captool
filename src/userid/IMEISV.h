/*
 * IMEISV.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IMEISV_H__
#define __IMEISV_H__

#include <boost/shared_ptr.hpp>
#include <cstddef> //size_t
#include <string>
#include <tr1/functional> // hash

#include "util/poolable.h"
#include "TBCD.h"

/**
 * Represent an IMEISV.
 */
class IMEISV : public TBCD
{
    public:
        /** Pointer type for safe exchange of IMEISV pointers */
        typedef boost::shared_ptr<IMEISV> Ptr;
        
        /**
         * Constructor possibly anonymizing IMEISV.
         *
         * @param tbcdString TBCD encoded IEISV
         * @param anonymize wheter to hash to reduced value space after encryption
         *
         * @note encryption key must be at least 16 bytes long
         */
        IMEISV (uint8_t* const & tbcdString, bool anonymize = false);
        
        /**
         * Destructor.
         */
        ~IMEISV();
        
        /** Return IMEI/TAC. */
        std::string const& tac() const;
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()
        
    private:
        /**
         * Anonymize the IMEISV to contain only the IMEI/TAC part.
         * @note The string representation should already be ready when anonymize() is called.
         */
        void anonymize();
        
        /** length of the IMEI/TAC field;  also number of bytes preserved when anonyimizing */
        static const unsigned IMEITAC_LENGTH = 4;
        
        /** internal representation of IMEI/TAC */
        std::string  tacrep;

        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(IMEISV)

std::ostream& operator<<(std::ostream&, const IMEISV::Ptr&);
bool operator== (const IMEISV::Ptr&, const IMEISV::Ptr&);
bool operator!= (const IMEISV::Ptr&, const IMEISV::Ptr&);

#endif
