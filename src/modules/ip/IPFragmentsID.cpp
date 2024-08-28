/*
 * IPFragmentsID.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "IPFragmentsID.h"

CAPTOOL_POOLABLE_INIT_POOL(IPFragmentsID, 30)

namespace std {

template<>
bool
equal_to<IPFragmentsID *>::operator() (IPFragmentsID * const& x, IPFragmentsID * const& y)
const
{
    if (x == y)
        return true;
    
    return
        x &&
        y &&
        (x->_id == y->_id) &&
        (x->_srcIP == y->_srcIP) &&
        (x->_dstIP == y->_dstIP) &&
        (x->_proto == y->_proto);
}

namespace tr1 {

template<>
std::size_t
hash<IPFragmentsID *>::operator() (IPFragmentsID * fragid)
const
{
    return fragid ? fragid->_id : 0;
}

}} // std::tr1::
