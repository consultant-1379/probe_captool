/*
 * AutoMem.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __AUTO_MEM_H__
#define __AUTO_MEM_H__

#include <cassert>
#include <cstdlib>
#include <sys/types.h>
#include <cstring>
#include "log.h"

/**
 * Helper class that acts as an auto-increasing buffer area.
 */
class AutoMem
{
    public:
        
        /**
         * Constructor.
         *
         * @param defaultLength default length of the buffer area
         */
        explicit AutoMem(u_int defaultLength);
        
        /** 
         * Destructor.
         */
        ~AutoMem();
        
        /**
         * Copies the given area to the beginning of the buffer.
         * Does not change anything if unsuccessful.
         *
         * @param ptr pointer to the memory to be copied
         * @param length length of portion to be copied
         * @return true on success
         */
        bool copy(const u_char *ptr, u_int length);
        
        /**
         * Copies the given area to the buffer with the given offset.
         * Does not change anything if unsuccessful.
         *
         * @param ptr pointer to the memory to be copied
         * @param offset offset to be used when copying
         * @param length length of portion to be copied
         * @return true on success
         */
        bool copy(const u_char *ptr, u_int offset, u_int length);
        
        /**
         * Returns the contents of the buffer.
         *
         * @param length location to copy the length of the packet to
         * 
         * @return pointer to the beginning of the buffer
         */
        const u_char *get(u_int *length);
        
        /**
         * Clears the buffer
         */
        void clear();
        
    private:
        
        /** pointer to the beginning of the buffer */
        const u_char *_pointer;
        
        /** length of the allocated memory for the buffer */
        u_int _allocated;
        
        /** length of the currently allocated memory of the buffer */
        u_int _length;
};

inline
AutoMem::AutoMem(u_int defaultLength = 1024)
    : _length(0)
{
    if (defaultLength > 0)
    {
        _pointer = (u_char *)malloc(defaultLength);
        _allocated = defaultLength;
    }
    else
    {
        _pointer = 0;
        _allocated = 0;
    }
}

inline
AutoMem::~AutoMem()
{
    free( (void *)_pointer );
}
    
inline bool
AutoMem::copy(const u_char *ptr, u_int length)
{
    assert(ptr != 0);
    
    return copy(ptr, 0, length);
}

inline bool
AutoMem::copy(const u_char *ptr, u_int offset, u_int length)
{
    assert(ptr != 0);
    
    if (offset + length > _allocated)
    {
        const u_char * p = (const u_char *) realloc((void *)_pointer, offset + length);
        if (!p)
            return false;
        _pointer = p;
        _allocated = offset + length;
    }
    
    assert(_allocated >= offset + length);
    
    memcpy((void *)(_pointer + offset), ptr, length);
    
    _length = offset + length;
    
    return true;
}

inline const u_char *
AutoMem::get(u_int *length)
{
    if (length != 0)
    {
        *length = _length;
    }
    
    return _pointer;
}

inline void
AutoMem::clear()
{
    _length = 0;
}

#endif //__AUTO_MEM_H__
