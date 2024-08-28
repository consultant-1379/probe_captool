/*
 * IMSI.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "IMSI.h"
#include "util/Hash.h"
#include <sstream>
#include <iomanip>
#include <algorithm> // min()

CAPTOOL_POOLABLE_INIT_POOL(IMSI, 10000)

IMSI::IMSI(uint8_t* const & tbcdString, std::string const & key, bool anonymize)
    : TBCD(tbcdString)
{
    if (key.size() > 0)
        encrypt(key);
    if (anonymize)
        this->anonymize();
}

IMSI::~IMSI()
{
}

void
IMSI::anonymize()
{
    /*
     * The probability of a collision within a US operator`s network (MSIN is 9 digit long) is 0
     * (assuming that Hash::hashValue() provides a perfect hash)
     *
     * For a non-US network (MSIN is 10 digit long), the collision probability can be calculated as follows:
     * Only one single bit of the MSIN is not covered by "b", therefore the hash of a given IMSI may collide
     * only with one other IMSI from the operator's IMSI range. Therefore, the probability that the hash of one
     * particular subscriber IMSI will colide with that of another IMSI within a network of "n" subscribers is
     * smaller than n / 10^10. This is only an upper bound, because the 4E9 possible values of "b" do not cover
     * the entire 32 bit range (2^32 ~ 4.29E9)
     *
     * Hence the following conservative lower bound can be derived on the probability of no collision
     * for a network with n subscribers:
     *
     * [1 - (n-1)/10^10] * [1 - (n-2)/10^10] * ... * [1 - 2/10^10] * [1 - 1/10^10]
     *
     * For 100k subscribers, this gives >60% probability of no collision at all.
     * Based on simulations, the average number of collisions evolves as follows with network size:
     *
     * 100k -> ~0
     * 200k -> ~1
     * 500k -> ~5
     * 1M -> ~20
     */

    // First 6 digits: (MCC + MOC + first one digit of MSIN for non-US operators), but from the 6th digit, only the most significant bit is used
    uint32_t a = (bytes[2] >> 4 & 0x08)  + (bytes[2] & 0x0f) * 10;
    a += (bytes[1] >> 4) * 100 + (bytes[1] & 0x0f) * 1000;
    a += (bytes[0] >> 4) * 10000 + (bytes[0] & 0x0f) * 100000;
    
    // Last 2 least significant bits of 6th digit + the remaining 9 digits of MSIN 
    uint32_t b = bytes[7] & 0x0f;
    b += (bytes[6] >> 4) * 10 + (bytes[6] & 0x0f) * 100;
    b += (bytes[5] >> 4) * 1000 + (bytes[5] & 0x0f) * 10000;
    b += (bytes[4] >> 4) * 100000 + (bytes[4] & 0x0f) * 1000000;
    b += (bytes[3] >> 4) * 10000000 + (bytes[3] & 0x0f) * 100000000;
    b += ((bytes[2] >> 4) & 0x03) * 1000000000;

    // Merge the two hashes
    uint64_t hash = Hash::hashValue(a) ^ Hash::hashValue(b);

    // Combine with the result the 3th bit of digit 6 (the only bit which was not incorporated into the hash so far)
    if (bytes[2] & 0x40)
    {
        hash |= (uint64_t)1 << 32;
    }
    bytes[1] = (bytes[1] & 0x0f) | ((hash / 1000000000) << 4);
    bytes[2]  =  (hash %= 1000000000) / 100000000;
    bytes[2] |= ((hash %= 100000000)  / 10000000) << 4;
    bytes[3]  =  (hash %= 10000000)   / 1000000;
    bytes[3] |= ((hash %= 1000000)    / 100000) << 4;
    bytes[4]  =  (hash %= 100000)     / 10000;
    bytes[4] |= ((hash %= 10000)      / 1000) << 4;
    bytes[5]  =  (hash %= 1000)       / 100;
    bytes[5] |= ((hash %= 100)        / 10) << 4;
    bytes[6]  = ((hash %= 10)         / 1) | TBCD_UNUSED << 4;
    bytes[7] = TBCD_UNUSED | TBCD_UNUSED << 4;
    mkstring();
}

void
IMSI::encrypt(std::string const & secret)
{
    unsigned keyLength = secret.size();
    
    if (keyLength == 0)
        return;
    
    const char * key = secret.c_str();
    
    // as in moniq
    
    uint i0 = 0; // pointer as counted actual digits in imsi
    uint i1; // pointer to the actual character of the key
    uint n;
    uint8_t c; // character storing the encrypted digits;

    for (uint i=0; i < TBCD_STRING_LENGTH; ++i)
    {
        // first digit in byte
        if ((bytes[i] & 0x0f) == TBCD_UNUSED)
        {
            break;
        }
        
        if (i0 >= NO_ENCRYPT_PREFIX)
        {
            i1 = abs(keyLength - i0 - 1) % keyLength;
            n = ( (uint)(key[i0 % keyLength]) + (uint)(bytes[i] & 0x0f)) % 10;
            c = (uint8_t)( (uint)(key[i1]/10 + n)  % 10 );
            bytes[i] = c | (bytes[i] & 0xf0);
        }
        
        
        // second digit in byte
        if ((bytes[i] >> 4) == TBCD_UNUSED)
        {
            break;
        }
        
        ++i0;
        
        if (i0 >= NO_ENCRYPT_PREFIX)
        {
            i1 = abs(keyLength - i0 - 1) % keyLength;
            n = ( (uint)(key[i0 % keyLength]) + (uint)(bytes[i] >> 4)) % 10;
            c = (uint8_t)( (uint)(key[i1]/10 + n)  % 10 );
            bytes[i] = (c << 4) | (bytes[i] & 0x0f);
        }
        
        ++i0;
    }
    
    mkstring();
}

bool
operator== (const IMSI::Ptr& a, const IMSI::Ptr& b)
{
    if (!a && !b)
        return true;
    return a ? a->operator==(*b.get()) : false;
}

bool
operator!= (const IMSI::Ptr& a, const IMSI::Ptr& b)
{
    return ! (a == b);
}

std::ostream&
operator<< (std::ostream& o, const IMSI::Ptr& id)
{
    return o << static_cast<const ID::Ptr&>(id);
}
