/*
 * ID.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __ID_H__
#define __ID_H__

#include <boost/shared_ptr.hpp>
#include <tr1/functional> // std::hash
#include <string>

/**
 * Represent a single idenitification number (e.g., user or equipment).
 *
 * @author Gábor Németh <gabor.a.nemeth@ericsson.com>
 */
class ID {
    
    public:
        
        typedef boost::shared_ptr<ID> Ptr;
        
        /**
         * Construct ID from a raw byte string.
         * @note Assumes supplied bytes are in host order.
         */
        ID (uint8_t* const&, std::size_t);
        
        virtual ~ID ();
        
        bool operator== (const ID&) const;
        
        bool operator!= (const ID&) const;
        
        /** Give string representation of the ID. */
        std::string const& str() const;
        
        /**
         * Return hash value of the ID.
         */
        std::size_t hashValue () const;
        
        /**
         * Return the bytes of the ID.
         */
        const uint8_t* raw() const;
        
        /**
         * Tell number of bytes in the ID.
         */
        std::size_t size() const;
        
    protected:
        /**
         * Generate internal string representation of the ID.
         * It creates hexadecimal transcript of the raw #bytes.
         */
        void mkstring();
        
        /**
         * Build the hash code for this ID.
         */
        void mkhash ();
        
        /** String representation of the ID */
        std::string  strrep;
        
        /** bytes of the ID in host order */
        uint8_t *    bytes;
        
        /** length of #bytes */
        std::size_t  length;
        
    private:
        /** hash value corresponding the raw ID */
        std::size_t  hash;
        
        ID (const ID&);
};

std::ostream& operator<<(std::ostream&, const ID&);

std::ostream& operator<<(std::ostream&, const ID::Ptr&);

bool operator== (const ID::Ptr&, const ID::Ptr&);
bool operator!= (const ID::Ptr&, const ID::Ptr&);

namespace std { namespace tr1 {
    template<> std::size_t hash<ID::Ptr>::operator() (ID::Ptr) const;
}}

#endif
