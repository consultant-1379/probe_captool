/*
 * poolable.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

/**
 * Defines macros for pooling objects using Boost::Pool.
 */

#ifndef __POOLABLE_H__
#define __POOLABLE_H__

#include <cstddef>
#include <cassert>

#include <boost/pool/pool.hpp>

#define CAPTOOL_POOLABLE_DECLARE_METHODS() \
static void *operator new(size_t size); \
static void *operator new[](size_t n); \
static void operator delete(void *p); \
static void operator delete[](void *p, size_t n); \

#define CAPTOOL_POOLABLE_DECLARE_POOL() \
static boost::pool<> s_memoryPool;

#define CAPTOOL_POOLABLE_DEFINE_METHODS( className ) \
inline void * \
className::operator new(size_t size) { \
    assert( size == sizeof(className) ); \
    return (void *)s_memoryPool.malloc(); \
} \
\
inline void * \
className::operator new[](size_t n) { \
    return (void *)s_memoryPool.ordered_malloc(n); \
} \
\
inline void \
className::operator delete(void *p) { \
    if (p != 0) \
    { \
        s_memoryPool.free(p); \
    } \
} \
\
inline void \
className::operator delete[](void *p, size_t n) { \
    if (p != 0) \
    { \
        s_memoryPool.free(p, n); \
    } \
}

#define CAPTOOL_POOLABLE_INIT_POOL( className , size ) \
boost::pool<> className::s_memoryPool(sizeof(className), size);

#endif // __POOLABLE_H__
