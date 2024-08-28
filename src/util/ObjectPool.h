/*
 * ObjectPool.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __OBJECT_POOL_H__
#define __OBJECT_POOL_H__

#include <cassert>

#include <list>

//if CAPTOOL_NO_OBJECT_POOL is defined, the pool uses new/delete instead of pooling
//#define CAPTOOL_NO_OBJECT_POOL

/**
 * Class representing a pool of objects of the given type.
 */
template <typename T>
class ObjectPool
{
    public:
        
        /**
         * Constructor.
         */
        ObjectPool();
        
        /**
         * Destructor.
         */
        ~ObjectPool();
        
        /**
         * Gets a free pool object from the pool
         *
         * @return pointer to a pool object
         */
        T* getObject();
        
        /**
         * Releases an object to the pool
         *
         * @param obj the object to be released
         */
        void freeObject(T* obj);
        
        /**
         * Returns the total number of allocated objects.
         *
         * @return total number of allocated objects
         */
        u_int getTotalAllocated();
        
        /**
         * Return number of allocated objects.
         */
        u_int size();

    protected:
        
        /** list of free objects currently in the pool */
        std::list<T *>  _freeObjects;
        
        /** list of all allocated arrays of objects */
        std::list<T* >  _allObjects;
        
        /** the chunksize used in this object pool */
        u_int             _totalAllocated;

        /** number of allocated objects */
        u_int             allocated;

        /** helper method for deleting object arrays */
        static void arrayDeleteObject(T* obj);
                    
    private:
        
        /** to prevent copying */
        ObjectPool(const ObjectPool<T>& src);
        
        /** to prevent copying */
        ObjectPool<T>& operator=(const ObjectPool<T>& rhs);
};

template <typename T>
ObjectPool<T>::ObjectPool()
    : _totalAllocated(0), allocated(0)
{
}

template <typename T>
ObjectPool<T>::~ObjectPool()
{
    
#ifndef CAPTOOL_NO_OBJECT_POOL
    
    //free all allocated objects
    for (typename std::list<T *>::const_iterator iter(_allObjects.begin()), end(_allObjects.end()); iter != end; ++iter)
    {
        delete (*iter);
    }
#endif
    
}

template <typename T>
inline T *
ObjectPool<T>::getObject()
{
    
    ++ allocated; // FIXME this is incorrect if new() fails;  drop this whole class anyway
    
// if pooling is disabled, returns a new T instance
#ifdef CAPTOOL_NO_OBJECT_POOL
    
    return new T();
    
#else    
    
    // no more free objects, allocate more
    
    if (_freeObjects.empty())
    {
        T *obj = new T();
        _allObjects.push_back(obj);
        ++_totalAllocated;
        return obj;
    }
    else
    {
        T *obj = _freeObjects.front();
        _freeObjects.pop_front();
        return obj;
    }
    
#endif
    
}

template <typename T>
inline void
ObjectPool<T>::freeObject(T* obj)
{
    assert(obj != 0);
    
    if (allocated)
      -- allocated;
    
// if no pooling is used, simply delete the object
#ifdef CAPTOOL_NO_OBJECT_POOL   
    
    delete(obj);
    
#else
    
    // put object back to free list
    _freeObjects.push_back(obj);
    
#endif    
    
}

template <typename T>
inline u_int
ObjectPool<T>::getTotalAllocated()
{
    return _totalAllocated;
}

template <typename T>
inline u_int
ObjectPool<T>::size()
{
    return allocated;
}

#endif // __OBJECT_POOL_H__
