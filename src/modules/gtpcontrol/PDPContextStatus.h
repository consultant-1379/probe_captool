/*
 * PDPContextStatus.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PDP_CONTEXT_STATUS_H__
#define __PDP_CONTEXT_STATUS_H__

/**
 * Represents the status of a PDPContext
 */
class PDPContextStatus
{
    public:
        
        /**
         * Status of a PDPContext
         */
        enum Status {
            OK,                 /**< active */
            PDP_CREATE_REQUEST, /**< the context is being created */
            PDP_UPDATE_REQUEST  /**< the context is being updated */
        };
        
        /**
         * Constructor.
         *
         * @param status the initial status
         * @param nsapi the primary nsapi of the PDPContext
         */
        PDPContextStatus(Status status, u_int8_t nsapi);
        
    private:
    
        /** the status */
        Status   _status;
        
        /** the nsapi */
        u_int8_t _nsapi;
        
        friend class PDPContext;
        friend class GTPControl;
};

inline
PDPContextStatus::PDPContextStatus(Status status, u_int8_t nsapi)
    : _status(status),
      _nsapi(nsapi)
{
}

#endif // __PDP_CONTEXT_STATUS_H__
