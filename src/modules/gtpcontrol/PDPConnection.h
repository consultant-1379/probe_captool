/*
 * PDPConnection.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PDP_CONNECTION_H__
#define __PDP_CONNECTION_H__

#include <cassert>
#include <sstream>
#include <arpa/inet.h>  

#include "util/poolable.h"

#include "ip/IPAddress.h"


/**
 * Identifies a PDPContext connection with a TEID and accompanying IPAddress.
 */
class PDPConnection
{
    public:
        
        /**
         * Constructor.
         *
         * @param teid the TEID of the connection in network byte order
         * @param ipTeidOwner the IP address of the connection
         */
        PDPConnection(u_int32_t teid, const IPAddress::Ptr & ipTeidOwner);
        
        /**
         * Checks whether the given PDPConnection represents the same connection as this one
         *
         * @param c the PDPConnection to compare
         *
         * @return true if the given PDPConnection represents the same connection as this one
         */
        bool equals(const PDPConnection *c) const;
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()
    private:
        
        /** the teid of the connection in network byte order */
        u_int32_t   _teid;

        /** the IPAddress of the connection */
        IPAddress::Ptr _ipTeidOwner;

        friend class PDPConnectionEquals;
        friend class PDPConnectionHasher;
        friend class PDPConnections;
        friend class PDPContext;
        friend class GTPControl;
    
        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(PDPConnection)

inline
PDPConnection::PDPConnection(u_int32_t teid, const IPAddress::Ptr & ipTeidOwner)
    : _teid(teid),
      _ipTeidOwner(ipTeidOwner)
{
        assert(teid != 0);
        assert(ipTeidOwner);
}

inline bool
PDPConnection::equals(const PDPConnection *c) const
{
    assert (c != 0);
    
    if (this == c)
    {
        return true;
    }
    
    return (
            this->_teid == c->_teid &&
            this->_ipTeidOwner->equals(c->_ipTeidOwner)
    );
    
}

#endif // __PDP_CONNECTION_H__
