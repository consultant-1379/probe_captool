/*
 * Summarizer.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __SUMMARIZER_H__
#define __SUMMARIZER_H__

#include <string>
#include "captoolpacket/CaptoolPacket.h"
#include <map>
#include <boost/pool/pool_alloc.hpp>
#include <tr1/unordered_map>
#include <utility>
#include <fstream>
#include "modulemanager/Module.h"
#include "libconfig.h++"
#include <ctime>
#include "ip/IPAddress.h"
#include "classification/TagContainer.h"
#include "userid/ID.h"

namespace captool {

/**
 * Module producing per user per application category traffic volume entries. Intended for online usage of CapTool (e.g., with PerfMon).
 * Application category is defined as flows having identical classification tags associated to them.
 * Totals are printed in one go at each call to openNewFiles()--i.e., at end of each collection period.
 * @todo getStatus()
 * @note Does not make much sense if used with FlowOutput because users can not be identified in that case.
 * @author Gábor Németh <gabor.a.nemeth@ericsson.com>
 * @par %Module configuration
 * @code
 *   summary:
 *   {
 *     type = "Summarizer";
 *     baseModule = "ip2";                      // count payload bytes from this module's payload
 *     connections = (
 *                     ("default", "dump")      // has default output only
 *                   );
 *     filePrefix = "out/summary"; 
 *     filePostfix = ".txt";
 *   };
 * @endcode
 */
class Summarizer : public captool::Module, public captool::FileGenerator
{
    
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit Summarizer(std::string name);
        
        /**
         * Destructor.
         */    
        virtual ~Summarizer();
        
        // inherited from Module
        Module* process(CaptoolPacket* captoolPacket);
        
        // inherited from Module
        //void getStatus(std::ostream *s, u_long runtime, u_int period);
        
        void openNewFiles();
        
    protected:
        
        // inherited from Module
        virtual void initialize(libconfig::Config* config);
        
        /** protocol the payload of which is to be counted into packets byte length */
        Module *          baseModule;
        
        /** prefix of the output file */
        std::string       filePrefix;
        
        /** postfix of the output file */
        std::string       filePostfix;
        
        /** stream for per user traffic volumes */
        std::ofstream     out;
        
        /** timestamp of current period start (seconds since Epoch) */
        std::time_t       start;
        
        /** timestamp of current period end (seconds since Epoch) */
        std::time_t       end;
        
        /** space delimited list of facet names */
        std::string       facetnames;
        
        /** Count of classification facets */
        size_t            facetcount;
        
        /** Output and clear all statistics in one go. */
        void flush();
        
        /** Statistics of flows already seen
         * @note It is technically possible that two flows with distinct tag sets will seem as having the same set (hash collision)
         * but the effect of it is negligible during summarization.
         */
        struct FlowStats
        {
            /** uplink bytes in the flow from the previous period */
            unsigned long long  upoffset;
            
            /** downlink bytes in the flow from the previous period */
            unsigned long long  downoffset;
            
            /** previously recorded hash code of classification tags */
            std::size_t         tags;
            
            FlowStats(unsigned long long up, unsigned long long down, std::size_t t) : upoffset(up), downoffset(down), tags(t) {}
        };
        
        /** type for storing flows that were already seen during this period */
        typedef std::tr1::unordered_map < Flow::Ptr, 
                                          FlowStats
                                        >   FlowMap;
        
        /** map for flows already seen */
        FlowMap           flows;
        
        /** User identification
         * Also stores user equipment (UE) type information string, practically TAC.
         * @note This is actually @em IP @em address identification, as there will be 
         * separate lines for each IP address associated to the same IMSI during the
         * whole period.
         */
        struct UserID
        {
            /** User identification string, practically IMSI */
            ID::Ptr             userid;
            /** Equipment identification, e.g., TAC */
            ID::Ptr             equipment;
            unsigned long long  ip;
            std::size_t		hash;
            
            UserID (ID::Ptr const& userid, const IPAddress::Ptr & ip, ID::Ptr const& equipment);
            
            bool operator== (const UserID& other) const;
        };
        
        /** User + application category identification */
        struct UserAppID
        {
            UserID       user;
            
            /** hash code of tag container */
            std::size_t  tags;
            
            /** TAB delimited string of tag values */
            std::string  tagstring;
            
            /** Construct from previously saved tag hash code */
            UserAppID(const UserID &uid, std::size_t t) : user(uid), tags(t) {}
            
            /** Construct from TagContainer properly */
            UserAppID(const UserID &, const TagContainer &);
            
            bool operator==(const UserAppID &) const;
        };
        
        /** Hash functor for UserAppID
         * @note It would not be necessary were UserID public for std::.
         */
        struct UserAppIDHasher : std::unary_function <UserAppID &, std::size_t>
        {
            std::size_t operator() (const UserAppID &) const;
        };
        
        /** Traffic volume associated to a user+flowtags pair */
        struct UserAppStats
        {
            /** uplink byte count */
            unsigned long long   up;
            
            /** downlink byte count */
            unsigned long long   down;
            
            UserAppStats() : up(0), down(0) {}
        };
        
        /** type for user+flowtags stats container */
        typedef std::tr1::unordered_map < UserAppID,
                                          UserAppStats,
                                          UserAppIDHasher
                                        >   UserAppMap;
        
        /** map of per user per application category (flowtags) traffic volumes */
        UserAppMap        userapps;
};

} // namespace captool

#endif // __SUMMARIZER_H__
