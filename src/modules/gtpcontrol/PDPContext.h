/*
 * PDPContext.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PDP_CONTEXT_H__
#define __PDP_CONTEXT_H__

#include <cassert>
#include <string>
#include <sstream>
#include <map>
#include <pcap.h>
#include <cstring> // memcpy
#include "ip/IPAddress.h"
#include "util/poolable.h"
#include "util/Timestamped.h"
#include "userid/IMSI.h"
#include "userid/IMEISV.h"
#include "PDPConnections.h"
#include "PDPConnection.h"
#include "PDPContextStatus.h"

/**
 * Represents a PDPContext with all its informations and GSN connections.
 */
class PDPContext : public Timestamped
{
    public:
        
        /**
         * Constructor.
         *
         * @param created the timestamp of the time the context was created
         * @param status the status of the control connection of this PDPContext
         * @param nsapi the nspai number of the control connection of this PDPContext
         * @param imsi the IMSI associated with this PDPContext
         * @param imeisv the IMEISV associated with this PDPContext
         */
        PDPContext(const struct timeval *created, PDPContextStatus::Status status, u_int8_t nsapi, const IMSI::Ptr & imsi, const IMEISV::Ptr & imeisv = IMEISV::Ptr());

        /**
         * Destructor.
         */
        ~PDPContext();

        /**
         * Returns true if the control connection is established in both directions.
         *
         * @return true if the connection is established in both directions.
         */
        bool isEstablished() const;
        
        /**
         * Returns the APN of this context.
         */
        const char * getAPN() const;

        /**
         * Returns the IMEI(SV) associated with this context.
         */
        const IMEISV::Ptr & getIMEI() const;

        /**
         * Returns a string representation of RAT type associated with this context.
         */
        const char * getRAT() const;

        /**
         * Returns the associated IMSI of the context
         */
        const IMSI::Ptr & getIMSI() const;
        
        const struct timeval getLastTimestamp() const;

        CAPTOOL_POOLABLE_DECLARE_METHODS()
    private:

        /** the time this context was created at */
        const struct timeval    _created;

        /** Timestamp of last user plane activity */
        struct timeval _lastActivity;

        /** the status of this PDPContext */
        PDPContextStatus _status;
        
        /** the nsapi associated with the primary PDP */
        u_int8_t   _primaryNsapi;

        /** the IMSI of this PDPContext */
        IMSI::Ptr _imsi;

        /** the IMSI of this PDPContext */
        IMEISV::Ptr _imeisv;

        /** the user plane IP address of the PDP context */
        IPAddress::Ptr _userIP;
        
        /** Max length of Access Point Name in the corresponding information element (TS 24.008) */
        static const u_int MAX_LENGTH_OF_APN = 102;

        /** Access point name of this PDP context */
        char _apn[MAX_LENGTH_OF_APN+1];

        /** RAT type (UTRAN = 1, GERAN = 2) */
        u_int8_t _ratType;
        
        /** User Location Information (MCC, MNC, LAC, CI/SAC) */
        std::string _loc;

        /** the control connections of the PDPContext */
        PDPConnections *_control;
        
        /** pair for storing nsapi number and PDPConnections objects */
        typedef std::pair<u_int8_t, PDPConnections *> DataConnectionsMapPair;
        
        /** map for mapping nsapis to their represented user plane PDPConnections */
        typedef std::map<u_int8_t, PDPConnections *> DataConnectionsMap;

        /** map of nsapis and their PDPConnections */
        DataConnectionsMap _datas;
        
        /** set Access Point Name */
        void setAPN(const u_int8_t * apn, u_int apn_length);
        
        /** Updated last activity timestamp */
        void updateTimestamp(const struct timeval timestamp);

        friend class GTPControl;
//        friend class GTPUser;

        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(PDPContext)

inline
PDPContext::PDPContext(const struct timeval *created, PDPContextStatus::Status status, u_int8_t nsapi, const IMSI::Ptr & imsi, const IMEISV::Ptr & imei)
    : _created(*created),
      _lastActivity(*created),
      _status(status, nsapi),
      _primaryNsapi(nsapi),
      _imsi(imsi),
      _imeisv(imei),
      _userIP(),
      _ratType(0),
      _control(0)
{
    assert(_primaryNsapi < 16);
    
    // set the "NA" string for APN (might be updated later)
    _apn[0] = 'n'; _apn[1] = 'a'; _apn[2] = 0;
    
    _loc = "na";
}

inline
PDPContext::~PDPContext()
{
    delete(_control);
    
    for (DataConnectionsMap::const_iterator iter(_datas.begin()), end(_datas.end()); iter != end; ++iter)
    {
        delete((PDPConnections *)iter->second);
    }
}

inline const struct timeval
PDPContext::getLastTimestamp() const
{
    return _lastActivity;
}

inline bool
PDPContext::isEstablished() const
{
    assert(_control != 0);
    
    return (_control->_conn1 != 0 && _control->_conn2 != 0);
}

inline
const
IMSI::Ptr &
PDPContext::getIMSI() const
{
    return _imsi;
}

inline
const IMEISV::Ptr &
PDPContext::getIMEI() const
{
    return _imeisv;
}

inline const char *
PDPContext::getAPN() const
{
    return _apn;
}

inline void
PDPContext::setAPN(const u_int8_t * apn, u_int apn_length) 
{
    u_int max_length = apn_length < MAX_LENGTH_OF_APN ? apn_length : MAX_LENGTH_OF_APN;
    u_int pos = 0;
    // Parsing APN labels as specified in 3GPP TS 23.003
    while (pos < max_length) {
	u_int label_length = apn[pos];
	memcpy(_apn + pos, apn + pos + 1, label_length);
	pos += label_length + 1;
	_apn[pos-1] = '.';
    }

    // Put string termination (replacing the terminating '.' character)
    _apn[max_length-1] = 0;
}

inline const char *
PDPContext::getRAT() const
{
    switch (_ratType) {
        case 0: return "na";
        case 1: return "UTRAN";
        case 2: return "GERAN";
        case 3: return "WLAN";
    }
    return "invalid_RAT";
}

inline void
PDPContext::updateTimestamp(const struct timeval timestamp)
{
    _lastActivity = timestamp;
}

#endif // __PDP_CONTEXT_H__
