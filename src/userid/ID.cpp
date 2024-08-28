/*
 * ID.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "ID.h"
#include <cstring>
#include <ostream> // ostream.operator<<(const char *)
#include "util/log.h"

ID::ID (uint8_t* const & raw, std::size_t len)
  : length(len)
{
    bytes = new uint8_t [len];
    if (! bytes)
    {
        length = 0;
        CAPTOOL_LOG_SEVERE ("No memory for ID")
    }
    if (raw)
    {
        std::memcpy((void*) bytes, raw, len);
        mkhash();
        mkstring();
    }
}

ID:: ID (const ID&)
{
}

ID:: ~ID ()
{
    delete bytes;
}

std::size_t
ID::size () const
{
    return length;
}

void
ID::mkstring ()
{
    strrep.clear();
    for (unsigned i = 0; i < length; ++i)
    {
        char digit = bytes[i] >> 4;
        strrep += '0' + digit;
        digit = bytes[i] & 0x0f;
        strrep += '0' + digit;
    }
}

void
ID::mkhash ()
{
    hash = 0;
    for (unsigned i = 0; i < length / 2; ++i)
        hash |= (bytes[i] ^ bytes[i + length/2]) << (i * 8);
}

bool
ID::operator== (const ID& other) const
{
    if (length != other.length)
        return false;
    return std::memcmp((void*) bytes, (void*) other.bytes, length) == 0;
}

bool
ID::operator!= (const ID& other) const
{
    return ! (*this == other);
}

std::size_t
ID::hashValue() const
{
    return hash;
}

const uint8_t*
ID::raw () const
{
    return bytes;
}

std::string const& 
ID::str() const
{
    return strrep;
}

std::ostream&
operator<< (std::ostream& o, const ID& id)
{
    return o << id.str();
}

std::ostream&
operator<< (std::ostream& o, const ID::Ptr& id)
{
    if (id)
        o << id->str();
    else
        o << "na";
    return o;
}

bool
operator== (const ID::Ptr& a, const ID::Ptr& b)
{
    if (!a && !b)
        return true;
    if (!a || !b)
        return false;
    return a->operator==(*b.get());
}

bool
operator!= (const ID::Ptr& a, const ID::Ptr& b)
{
    return ! (a == b);
}

namespace std { namespace tr1 {
template<>
std::size_t
hash<ID::Ptr>::operator() (ID::Ptr id) const
{
    return id ? id->hashValue() : 0;
}
}} // std::tr1::
