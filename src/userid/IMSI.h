/*
 * IMSI.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __IMSI_H__
#define __IMSI_H__

#include <boost/shared_ptr.hpp>
#include <cstddef> //size_t
#include <string>
#include <tr1/functional> // hash

#include "util/poolable.h"
#include "TBCD.h"

/**
 * Represent an IMSI.
 *
 */
class IMSI : public TBCD
{
    public:
        /** Pointer type for safe exchange of IMSI pointers */
        typedef boost::shared_ptr<IMSI> Ptr;
        
        /**
         * Constructor possibly encrypting IMSI.
         *
         * @param tbcdString TBCD encoded IMSI
         * @param key encryption key
         * @param anonymize wheter to hash to reduced value space after encryption
         *
         * @note encryption key must be at least 16 bytes long
         */
        IMSI (uint8_t* const & tbcdString, std::string const & key = std::string(), bool anonymize = false);
        
        /**
         * Destructor.
         */
        ~IMSI();
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()
        
    private:
        /**
         * Encrypts the IMSI with the given key
         *
         * @param key encription key
         *
         * @note encryption key must be at least 16 bytes long
         */
        void encrypt(std::string const & key);

        /** do not encrypt the first number of digits */
        static const unsigned NO_ENCRYPT_PREFIX = 3;

        /**
         * Anonymize the stored representation of the IMSI by applying a one way hash.
         * Note that this is a true irreversible operation - multiple IMSIs may map
         * to the same representation - however, the probability of a collision within
         * an operator's network is very small.
         *
         * @note The string representation should already be ready when anonymize() is called.
         */
        void anonymize();

        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(IMSI)

std::ostream& operator<<(std::ostream&, const IMSI::Ptr&);
bool operator== (const IMSI::Ptr&, const IMSI::Ptr&);
bool operator!= (const IMSI::Ptr&, const IMSI::Ptr&);

#endif
