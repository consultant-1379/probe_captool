/*
 * TimeSortedList.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __TIMESORTED_LIST_H__
#define __TIMESORTED_LIST_H__

#include <boost/shared_ptr.hpp>
#include <boost/pool/pool_alloc.hpp>
#include <boost/function.hpp>
#include <tr1/unordered_map>
#include <utility>
#include <functional>
#include <time.h>

/**
 * Container template for sorted list of key-value pairs.
 * Defines a method to remove timed out elements.
 *
 * @note All methods ignore mapped values pointing to NULL.
 *
 * @tparam Key key type 
 * @tparam T mapped type (NB: should be a Timesorted type)
 * @tparam Hash hasher functor
 * @tparam Pred key equality comparator type
 */
template<class Key, class T, class Hash /*= hash<Key>*/, class Pred /*= std::equal_to<Key>*/ > 
class TimeSortedList {
    
    public:
        
        /** mapped value type;  it is forced to be a shared pointer */
        typedef boost::shared_ptr<T> value_type;
        
        TimeSortedList();
        
        ~TimeSortedList();
        
        /** Number of elements in the list. */
        size_t size() const;
        
        /**
         * Add new key-value pair to the map, and make it the last in the list.
         */
        void insert(Key &, const value_type);
        
        /**
         * Move element to the end of the list.
         */
        void moveToEnd(Key);
        
        /**
         * Remove timed out pairs from the map. 
         * Give time=0 to force all elements to time out.
         *
         * @param time pointer to a timeval structure representing current time
         * @param cleanupfunc callback function for to-be-removed elements
         */
        void cleanup(const struct timeval * time, boost::function<void (const T *)> & callback);
        
        /** Remove timed out flows without a callback.
         * @todo Make this with a default argument to the other cleanup()
         */
        void cleanup(const struct timeval * time);
        
        /**
         * Look up mapped object based on its key.
         *
         * @return shared pointer to the stored structure
         */
        value_type get(Key) const;
        
        /**
         * Set timeout parameter.
         */
        void setTimeout(time_t);
        
        class input_iterator;
        friend class input_iterator;
        
        /** First element of the list. */
        input_iterator   begin() const;
        
        /** One past-the-last element of the flow list. */
        input_iterator   end() const;
        
    private:
        
        /** list element structure for sorted list */
        struct TimeSortedListElement {
            std::pair<value_type,Key> elem;
            TimeSortedListElement*    prev;
            TimeSortedListElement*    next;
        };
        
        /** head of linked list */
        TimeSortedListElement*        first;
        
        /** tail of linked list */
        TimeSortedListElement*        last;
        
        /** map of key-value pairs */
        typedef std::tr1::unordered_map <Key, 
                                         std::pair<value_type, TimeSortedListElement*>,
                                         Hash, 
                                         Pred, 
                                         boost::fast_pool_allocator<std::pair<Key, std::pair<value_type, TimeSortedListElement*> > >
                                        >    MapType;

        MapType                       map;
        
        /** seconds before an element of the list times out */
        time_t                        timeout;
        
        /** empty callback function for cleanup() */
        struct nullcallback
        {
            void operator() (const T *) const {}
        };
};

template <class K, class T, class H, class P>
TimeSortedList<K,T,H,P>::TimeSortedList()
  : first(0),
    last(0)
{
}

template <class K, class T, class H, class P>
TimeSortedList<K,T,H,P>::~TimeSortedList()
{
    cleanup(0);
}

template <class K, class T, class H, class P>
void
TimeSortedList<K,T,H,P>::insert(K & id, const value_type val)
{
    if (val.get() == 0) return;
    
    TimeSortedListElement* fe = new TimeSortedListElement();
    fe->elem = std::make_pair(val,id);
    
    if (first == 0) first = fe;
    
    if (last != 0) last->next = fe;
    
    fe->prev = last;
    fe->next = 0;
    last = fe;
    
    map.insert( std::make_pair(id, std::make_pair(val, fe)) );
}

template <class K, class T, class H, class P>
size_t
TimeSortedList<K,T,H,P>::size() const
{
    return map.size(); // BTW is it possible that map size differs from list size?  shouldn't be
}

template <class K, class T, class H, class P>
typename TimeSortedList<K,T,H,P>::value_type
TimeSortedList<K,T,H,P>::get(K id) const
{
//    if (id == 0) return value_type();
    
    typename MapType::const_iterator i = map.find(id);
    
    return i != map.end() ? (i->second).first : value_type();
}

template <class K, class T, class H, class P>
void
TimeSortedList<K,T,H,P>::moveToEnd(K id)
{
    typename MapType::const_iterator pos = map.find(id);
    
    if (pos == map.end()) return;
    
    TimeSortedListElement* fe = (pos->second).second;
    
    if (last != fe) // needs moving only if not the last flow already
    {
        if (fe->prev != 0) fe->prev->next = fe->next;
        else first = fe->next;
        
        if (fe->next != 0) fe->next->prev = fe->prev;
        
        if (last != 0) last->next = fe;
        
        fe->prev = last;
        last = fe;
        fe->next = 0;
    }
}

template <class K, class T, class H, class P>
void
TimeSortedList<K,T,H,P>::cleanup(const struct timeval * time)
{
    boost::function<void (const T *)> f = nullcallback();
    cleanup(time, f);
}

template <class K, class T, class H, class P>
void
TimeSortedList<K,T,H,P>::cleanup(const struct timeval * time, boost::function<void (const T *)> & callback)
{
    while (first != 0)
    {
        const TimeSortedListElement* fe = first;
        
        if ( time == 0 || (    timeout != 0
                            && time->tv_sec > (fe->elem).first->getLastTimestamp().tv_sec + timeout
                          )
           )
        {
            callback((fe->elem).first.get());
            
            first = fe->next;
            if (first == 0) last = 0;
            else first->prev = 0;
            
            map.erase((fe->elem).second);
            delete fe;
        }
        else
        {
            break;
        }
    }
}

template <class K, class T, class H, class P>
void
TimeSortedList<K,T,H,P>::setTimeout(time_t timeout)
{
    this->timeout = timeout;
}

/**
 * Input iterator for elements of the sorted list.
 * @todo fix end() if reverse iterators ever will be used
 */
template <class K, class T, class H, class P>
class TimeSortedList<K,T,H,P>::input_iterator
{
  public:
    
    input_iterator() : current(0) {}
    
    input_iterator(typename TimeSortedList<K,T,H,P>::TimeSortedListElement* other) : current(other) {}
    
    input_iterator(const input_iterator& other) : current(other.current) {}
    
    input_iterator& operator++ ()
    {
        if (current) current = current->next;
        return *this;
    }
    
    input_iterator& operator++ (int)
    {
        return operator++();
    }
    
/*
    const F& operator* () const
    {
        return current->flow.get();
    }
*/
    
    const value_type operator-> () const
    {
        return (current->elem).first;
    }
    
    bool operator== (const input_iterator& other)
    {
        return current == other.current;
    }
    
    bool operator!= (const input_iterator& other)
    {
        return current != other.current;
    }
    
  private:
    
    typename TimeSortedList<K,T,H,P>::TimeSortedListElement*   current;
};

template <class K, class T, class H, class P>
typename TimeSortedList<K,T,H,P>::input_iterator
TimeSortedList<K,T,H,P>::begin() const
{
    return typename TimeSortedList<K,T,H,P>::input_iterator(first);
}

template <class K, class T, class H, class P>
typename TimeSortedList<K,T,H,P>::input_iterator
TimeSortedList<K,T,H,P>::end() const
{
    return typename TimeSortedList<K,T,H,P>::input_iterator(); // ugly but will do until no reverse iterators are used
}

#endif
