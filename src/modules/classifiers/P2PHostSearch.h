/*
 * P2PHostSearch.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __P2P_HOST_SEARCH_H__
#define __P2P_HOST_SEARCH_H__

#include <map>
#include <functional>

#include "time.h"

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#include "util/Timestamped.h"
#include "util/TimeSortedList.h"

#include "classification/Classifier.h"

using std::map;

/**
 * Describers server port state (last activity and assigned tags).
 */
class HostTimestamp : public Timestamped
{
    public:

        HostTimestamp();

        HostTimestamp(const timeval& timestamp);

        ~HostTimestamp();

        /** Return time of last packet arrival in the flow. */
        const struct timeval getLastTimestamp() const;

    private:

        /** the time of the last activity associated with the given server port */
        struct timeval         _timestamp;

        friend class P2PHostSearch;
};

inline
HostTimestamp::HostTimestamp()
{
}

inline
HostTimestamp::HostTimestamp(const timeval& timestamp)
    : _timestamp(timestamp)
{
}

inline
HostTimestamp::~HostTimestamp()
{
}

inline const struct timeval
HostTimestamp::getLastTimestamp() const
{
    return _timestamp;
}


/**
 * Module to tag otherwise unidentified traffic between P2P hosts as P2P.
 * @par %Module configuration
 * @code  
 *   p2p:
 *   {
 *     type = "P2PHostSearch";
 *     connections = (
 *                    ("default", "dispatcher2")
 *                   );
 *     timeout = 900;  // Server ports time out in nn seconds
 *   };
 * @endcode
 */
class P2PHostSearch : public captool::Module, public Classifier
{
    public:

        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */
        explicit P2PHostSearch(std::string name);

        /**
         * Destructor.
         */
        ~P2PHostSearch();

        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);

    protected:

        void initialize(libconfig::Config* config);
        void configure (const libconfig::Setting &);
        void getStatus(std::ostream *s, u_long runtime, u_int period);
        void registerSignature(unsigned blockId, const Signature * signature);

    private:

        /** Maps host IP addresses (represented as u_int32_t) to last activity timestamps */
        typedef TimeSortedList<unsigned, HostTimestamp, std::tr1::hash<unsigned>, std::equal_to<unsigned> > P2PHostList;

        /** Maps to P2P application classes their P2P host list */
        map<unsigned, P2PHostList*> _p2pHostLists;
        
        /** Timeout value [sec] for inactivity timer in host lists */
        unsigned _timeout;

        /** The sigId used for P2P host search meta signatures (the same ID should be used within each P2P application class block) */
        unsigned _sigId;

        /** Specifies how often availability of P2P host matches should be checked. E.g. 1000 means that this will be performed for every 1000th packet of a given flow */
        unsigned _recheckPeriod;

        const static unsigned DEFAULT_HOST_TIMEOUT;
};



#endif /* __P2P_HOST_SEARCH_H__ */
