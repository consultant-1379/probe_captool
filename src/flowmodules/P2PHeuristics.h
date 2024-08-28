/*
 * P2PHeuristics.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __P2P_HEURISTICS_H__
#define __P2P_HEURISTICS_H__

#include <string>
#include <ostream>
#include <fstream>
#include <map>

#include <boost/intrusive_ptr.hpp>
#include <boost/dynamic_bitset.hpp>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "filemanager/FileGenerator.h"

#include "userid/ID.h"
#include "util/RefCounter.h"


using std::string;
using std::ostream;

class P2PHeuristicsDescriptor : public RefCounter
{
    public:
        
        typedef boost::intrusive_ptr<P2PHeuristicsDescriptor> Ptr;
        
        P2PHeuristicsDescriptor(u_int ipMapSize);
        
        void update(const Flow *);

    private:

        u_int               _numberOfFlows;

        u_long              _bytesUl;

        u_long              _bytesDl;

        dynamic_bitset<>    _ipBitmap;

        friend ostream& operator<<(ostream&, const P2PHeuristicsDescriptor&);
};

inline
P2PHeuristicsDescriptor::P2PHeuristicsDescriptor(u_int ipMapSize) :
    _numberOfFlows(0),
    _bytesUl(0),
    _bytesDl(0),
    _ipBitmap(dynamic_bitset<>(ipMapSize))
{
}

inline
void 
P2PHeuristicsDescriptor::update(const Flow* flow)
{
    ++_numberOfFlows;
    _bytesUl += flow->getUploadBytes();
    _bytesDl += flow->getDownloadBytes();
    _ipBitmap.set(flow->getID()->getDestinationIP()->getRawAddress() % _ipBitmap.size());
}

/**
 * Module to collect per subscriber flow data for P2P heuristic analyses.
 */
class P2PHeuristics : public captool::Module, public captool::FileGenerator
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit P2PHeuristics(string name);
        
        /**
         * Destructor.
         */    
        virtual ~P2PHeuristics();
        
        // inherited from Module
        Module* process(const Flow* flow);
        
        // inherited from FileGenerator
        void openNewFiles();

    protected:

        // inherited from Module
        void initialize(libconfig::Config* config);

        // inherited from Module
        void configure (const libconfig::Setting &);
        
    private:
    
        /** Write out statistics for current period and reset counters */
        void writeStats();

        /** prefix of the output file */
        std::string       _filePrefix;
        
        /** postfix of the output file */
        std::string       _filePostfix;
        
        /** stream to write the output file to */
        std::ofstream     _fileStream;
        
        /** size of the current output file */
        u_long            _currentFileSize;
        
        /** log entries are printed only if this is set to true */
        bool _outputEnabled;
        
        /** Size of bloom filter used to track different peers */
        u_int             _ipMapSize;
        
        /** Maps P2PHeuristicsDescriptors to subscriber IDs */
        typedef std::map<ID::Ptr, P2PHeuristicsDescriptor::Ptr> HeuristicsMap;
        
        HeuristicsMap     _heuristicsMap;
        
        /** start time of current period (in seconds since epoch) */
        u_long            _periodStart;

        /** last flow end timestamp within current period (in seconds since epoch) */
        u_long            _periodEnd;
};

#endif // __P2P_HEURISTICS_H__
