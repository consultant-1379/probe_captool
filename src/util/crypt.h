/*
 * crypt.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CAPTOOL_CRYPT_H__
#define __CAPTOOL_CRYPT_H__

#include <string>
#include <iostream>
#include <termios.h> // setting echo off
#include <unistd.h>  // and back on
#include "log.h"

/**
 * Turn terminal echo on/off.
 */
void
setecho (bool on)
{
    termios t;
    tcgetattr(STDIN_FILENO, &t);
    if (on)
        t.c_lflag |= ECHO;
    else
        t.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &t))
        CAPTOOL_LOG_WARNING("Unable to turn terminal echo " << (on ? "on." : "off.  Password will be echoed!"))
}

/**
 * Read secret key from standard input.
 * Echo is turned off before reading.
 */
std::string
getkey ()
{
    std::string key;
    std::cout << "Enter encryption key: ";
    setecho(false);
    std::cin >> key;
    setecho(true);
    std::cout << std::endl;
    return key;
}

/**
 * Create encoder block.
 *
 * Random number generation is inlined to guarantee same behavior always.
 */
void
fillblock (const std::string & key, char* const bytes, std::size_t n)
{
    /** FNV-1a hashing */
    std::size_t hash = 2166136261UL;
    for (char * keychars = const_cast<char*>(key.c_str()); *keychars != '\0';)
    {
        std::size_t x = 0;
        for (unsigned j = 0; j < sizeof(std::size_t) && *keychars != '\0'; ++j, ++keychars)
            x |= *keychars * (0xff << (j * 8)); // TBD: this loses significant bits
        hash ^= x;
        hash *= 16777619UL;
    }
    
    for (std::size_t i = 0; i < n; i += sizeof(std::size_t))
    {
        for (unsigned j = 0; j < sizeof(std::size_t) && i + j < n; ++j)
            bytes[i + j] = hash >> (j * 8);
        hash = hash * 1664525L + 1013904223L; /** From Numerical Recipies in C p.284 (based on Knuth and Lewis)
                                                  Actually for 32-bit only. */
    }
}

/**
 * Pretty basic stream encryptor.
 */
void
encrypt (std::istream & in, std::ostream & out)
{
    const std::string key = getkey();
    static const std::size_t len = 100000;
    char * keychars = new char [len];
    fillblock(key, keychars, len);
    char * datachars = new char [len];
    char * outchars = new char [len];
    while (in.good())
    {
        in.read(datachars, len);
        std::size_t reallen = in.gcount();
        for (std::size_t i = 0; i < reallen; ++i)
            outchars[i] = keychars[i] ^ datachars[i];
        out.write(outchars, reallen);
    }
    delete keychars;
    delete datachars;
    delete outchars;
}

/**
 * Even simpler stream decryptor.
 */
void
decrypt (std::istream & in, std::ostream & out)
{
    encrypt(in, out);
}

#endif // this header file
