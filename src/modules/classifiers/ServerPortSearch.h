/*
 * ServerPortSearch.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __SERVER_PORT_SEARCH_H__
#define __SERVER_PORT_SEARCH_H__

#include <string>

#include "time.h"

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"
#include "classification/ClassificationMetadata.h"
#include "classification/Classifier.h"

#include "util/poolable.h"
#include "util/Timestamped.h"
#include "util/TimeSortedList.h"

/**
 * Represents a server/peer port by a triplet (IP, port, transport type).
 */
class ServerPort
{
    
    public:

        ServerPort();
        
        ServerPort(u_int32_t ip, u_int16_t port, u_int8_t protocol);
        
        ~ServerPort();
 
        CAPTOOL_POOLABLE_DECLARE_METHODS()
       
    private:
        
        /** ip address of server/peer */
        u_int32_t _ip;
        
        /** server/peer port */
        u_int16_t _port;
        
        /** protocol type */
        u_int8_t  _protocol;
        
        friend class ServerPortEquals;
        friend class ServerPortHasher;

        CAPTOOL_POOLABLE_DECLARE_POOL()
    
};

CAPTOOL_POOLABLE_DEFINE_METHODS(ServerPort)

inline
ServerPort::ServerPort()
    : _ip(0),
      _port(0),
      _protocol(0)
{
}

inline
ServerPort::ServerPort(u_int32_t ip, u_int16_t port, u_int8_t protocol)
    : _ip(ip),
      _port(port),
      _protocol(protocol)
{
}

inline
ServerPort::~ServerPort()
{
}

/**
 * Helper class for comparing two ServerPort objects.
 */
class ServerPortEquals
{
    public:
        
        /**
         * Compares two ServerPort objects.
         *
         * @param spA a ServerPort object
         * @param spB a ServerPort object
         *
         * @return true if the two ServerPort objects represent the same server port
         */
        bool operator()(const ServerPort &spA, const ServerPort &spB) const;
};

inline bool
ServerPortEquals::operator()(const ServerPort &spA, const ServerPort &spB) const
{
    return spA._port == spB._port && spA._protocol == spB._protocol && spA._ip == spB._ip;
}

/**
 * Helper class for generating hash value for a ServerPort object.
 */
class ServerPortHasher
{
    public:
        
        /**
         * Returns a hash value for the given ServerPort object.
         *
         * @param fid the ServerPort
         *
         * @return the hash value
         */
        size_t operator()(const ServerPort &sp) const;
};

inline size_t
ServerPortHasher::operator()(const ServerPort &sp) const
{
    return (size_t)(sp._ip + sp._port + sp._protocol);
}

/**
 * Describers server port state (last activity and assigned tags).
 */
class ServerPortDescriptor : public Timestamped
{
    public:

        ServerPortDescriptor();

        ServerPortDescriptor(const timeval& timestamp, set<unsigned> blockIds);
    
        ~ServerPortDescriptor();
        
        /** Return time of last packet arrival in the flow. */
        const struct timeval getLastTimestamp() const;
        
        CAPTOOL_POOLABLE_DECLARE_METHODS()

    private:
        
        /** the time of the last activity associated with the given server port */
        struct timeval         _timestamp;

        /** the tag associated with this server port */
        set<unsigned>               _blockIds;

        friend class ServerPortSearch;
        
        CAPTOOL_POOLABLE_DECLARE_POOL()
};

CAPTOOL_POOLABLE_DEFINE_METHODS(ServerPortDescriptor)

inline
ServerPortDescriptor::ServerPortDescriptor()
{
}

inline
ServerPortDescriptor::ServerPortDescriptor(const timeval& timestamp, set<unsigned> blockIds)
    : _timestamp(timestamp),
      _blockIds(blockIds)
{
}

inline
ServerPortDescriptor::~ServerPortDescriptor()
{
}

inline const struct timeval
ServerPortDescriptor::getLastTimestamp() const
{
    return _timestamp;
}

/**
 * Classification module looking for known server ports.
 * The module learns common servers and ports, and adds hints when an already
 * known server port is found.
 * @par %Module configuration
 * @code
 * serverportsearch:
 * {
 *     type = "ServerPortSearch";
 *
 *     connections = (
 *                     ("default", "p2phostsearch")
 *     );
 *
 *     timeout = 120;                                  // Server port entries time out nn second after receiving the last packet for the given port
 * };
 * @endcode
 */
class ServerPortSearch : public captool::Module, public Classifier
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit ServerPortSearch(std::string name);
        
        /**
         * Destructor.
         */    
        ~ServerPortSearch();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
    protected:
        
        void initialize(libconfig::Config* config);

        virtual void configure (const libconfig::Setting &);
        
        void getStatus(std::ostream *s, u_long runtime, u_int period);

    private:
    
        typedef TimeSortedList<ServerPort, ServerPortDescriptor, ServerPortHasher, ServerPortEquals> ServerPortList;
        
        ServerPortList _serverPortList;
        
        unsigned _sigId;
};


#endif // __SERVER_PORT_SEARCH_H__
