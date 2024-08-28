/*
 * TBCD.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "TBCD.h"

TBCD::TBCD (uint8_t* const & raw)
  : ID (raw, TBCD_STRING_LENGTH)
{
    mkstring();
}

TBCD:: ~TBCD ()
{
}

void
TBCD::mkstring ()
{
    strrep.clear();
    for (unsigned i = 0; i < length; ++i)
    {
        char digit = bytes[i] & 0x0f;
        if (digit == TBCD_UNUSED)
            break;
        strrep += '0' + digit;
        digit = bytes[i] >> 4;
        if (digit == TBCD_UNUSED)
            break;
        strrep += '0' + digit;
    }
}

std::ostream&
operator<< (std::ostream& o, const TBCD::Ptr& id)
{
    return o << static_cast<const ID::Ptr&>(id);
}

bool
operator== (const TBCD::Ptr& a, const TBCD::Ptr& b)
{
    if (!a && !b)
        return true;
    if (!a || !b)
        return false;
    return a->operator==(*b.get());
}

bool
operator!= (const TBCD::Ptr& a, const TBCD::Ptr& b)
{
    return ! (a == b);
}

namespace std { namespace tr1 {
template<>
std::size_t
hash<TBCD::Ptr>::operator() (TBCD::Ptr id) const
{
    return id ? id->hashValue() : 0;
}
}} // std::tr1::
