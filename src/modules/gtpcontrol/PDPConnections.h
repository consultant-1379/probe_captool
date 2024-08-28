/*
 * PDPConnections.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PDP_CONNECTIONS_H__
#define __PDP_CONNECTIONS_H__

#include <string>
#include <sstream>

#include "util/poolable.h"

#include "PDPConnection.h"

class PDPContext;

/**
 * Represents a pair of PDPConnection objects representing a bidirectional connection between GSNs.
 */
class PDPConnections
{
    public:
        
        /**
         * Constructor.
         */
        PDPConnections();
        
        /**
         * Destructor.
         */
        ~PDPConnections();

        CAPTOOL_POOLABLE_DECLARE_METHODS()
    private:
        
        /** 
         * The status of the connection
         */
        enum PDPConnectionsStatus {
            CREATE_REQUESTED,       /**< a create request has been sent for the connection */
            UPDATE_REQUESTED,       /**< an update request has been sent for the connection */
            DELETE_REQUESTED,       /**< a delete request has been sent for the connection */
            CREATED                 /**< the connection is created and is active */
        };

        /** one direction of the bidirectional connection */
        PDPConnection *_conn1;
        
        /** the other direction of the bidirectional connection */
        PDPConnection *_conn2;
        
        friend class PDPContext;
        friend class GTPControl;
        
        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(PDPConnections)


inline
PDPConnections::PDPConnections()
    : _conn1(0),
      _conn2(0)
{
}

inline
PDPConnections::~PDPConnections()
{
    delete(_conn1);
    delete(_conn2);
}

#endif // __PDP_CONNECTIONS_H__
