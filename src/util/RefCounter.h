/*
 * RefCounter.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __REFCOUNTER_H__
#define __REFCOUNTER_H__

#include <boost/intrusive_ptr.hpp>

class RefCounter;

namespace boost
{
    void intrusive_ptr_add_ref (RefCounter *);
    void intrusive_ptr_release (RefCounter *);
}

/**
 * Class for storing the number of references to any intsance.
 * It is meant for use with ::boost::intrusive_ptr.
 * Based on http://www.codeproject.com/KB/stl/boostsmartptr.aspx by <em>peterchen</em>.
 *
 * @author Gábor Németh <gabor.a.nemeth@ericsson.com>
 */
class RefCounter
{
  private:
    unsigned long long count;
    friend void ::boost::intrusive_ptr_add_ref (RefCounter *);
    friend void ::boost::intrusive_ptr_release (RefCounter *);

  public:
    RefCounter () : count(0) {}
    virtual ~RefCounter () {}
};

namespace boost
{

inline
void
intrusive_ptr_add_ref (RefCounter * r)
{
    ++ (r->count);
}

inline
void
intrusive_ptr_release (RefCounter * r)
{
    if (-- (r->count) == 0)
        delete r;
}
} // boost::

#endif
