/*
 * IMEISV.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "IMEISV.h"

#include "util/log.h"

#include <stdexcept>
#include <algorithm> // min

CAPTOOL_POOLABLE_INIT_POOL(IMEISV, 10000)

IMEISV::IMEISV(uint8_t* const & tbcdString, bool anonymize)
    : TBCD(tbcdString)
{
    if (anonymize)
        this->anonymize();
    (tacrep = strrep).erase(IMEITAC_LENGTH * 2);
}

IMEISV::~IMEISV()
{
}

std::string const&
IMEISV:: tac() const
{
    return tacrep;
}

void
IMEISV::anonymize()
{
    for (unsigned i = IMEITAC_LENGTH; i < TBCD_STRING_LENGTH; ++i)
        bytes[i] = TBCD_UNUSED | (TBCD_UNUSED << 4);
    try 
    {
        strrep.erase(IMEITAC_LENGTH * 2);
    }
    catch (std::out_of_range& e) 
    {
        CAPTOOL_LOG_WARNING("Invalid IMEISV: " << strrep)
    }
}

bool
operator== (const IMEISV::Ptr& a, const IMEISV::Ptr& b)
{
    if (!a && !b)
        return true;
    return a ? a->operator==(*b.get()) : false;
}

bool
operator!= (const IMEISV::Ptr& a, const IMEISV::Ptr& b)
{
    return ! (a == b);
}

std::ostream&  
operator<< (std::ostream& o, const IMEISV::Ptr& id)
{
    return o << static_cast<const ID::Ptr&>(id);                 
}
