/*
 * Hash.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __HASH_H__
#define __HASH_H__

/**
 * Helper class to compute hash values
 */
class Hash
{

    public:

        /**
         * Computes the hash of a 32 bit integer
         *
         * @param value the integer whose hash should be computed
         * @return the computed hash value
         */
        static uint32_t hashValue(uint32_t value);
};

inline uint32_t
Hash::hashValue(uint32_t value)
{
    // Robert Jenkins' 32 bit integer hash function
    // See http://www.concentric.net/~Ttwang/tech/inthash.htm
    uint32_t a = value;
    a = (a+0x7ed55d16) + (a<<12);
    a = (a^0xc761c23c) ^ (a>>19);
    a = (a+0x165667b1) + (a<<5);
    a = (a+0xd3a2646c) ^ (a<<9);
    a = (a+0xfd7046c5) + (a<<3);
    a = (a^0xb55a4f09) ^ (a>>16);
    return a;
}

#endif /* __HASH_H__ */
