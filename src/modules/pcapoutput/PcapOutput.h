/*
 * PcapOutput.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __PCAP_OUTPUT_H__
#define __PCAP_OUTPUT_H__

#include <string>
#include <pcap.h>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "filemanager/FileGenerator.h"
#include "captoolpacket/CaptoolPacket.h"

/**
 * Module for saving packets in @em pcap format.
 * @par %Module configuration
 * @code
 * dump:
 * {
 *   type = "PcapOutput";
 * 
 *   baseModule = "ip2";        // dump payload including headers from this module
 *   snapLength = 60;           // snaplength to use (0 = no snap)
 *   flowPackets = 0;           // dump how many packets of each flow? (0 = all)
 *   fixHeaders = true;         // fix invalidated headers? (e.g. after defragmentation)
 *   filePrefix = "out/user";   // prefix of output files
 *   filePostfix = ".pcap";     // postfix of output files (including extension)
 *   maxFileSize = 0;           // maximum output file size; 0 = inf
 *   outputEnabled = false;     // enable/disable output
 * };
 * @endcode
 */
class PcapOutput : public captool::Module, public captool::FileGenerator
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit PcapOutput(std::string name);
        
        /**
         * Destructor.
         */    
        ~PcapOutput();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        // inherited from FileGenerator
        void openNewFiles();
        
    protected:
        
        void initialize(libconfig::Config *);
        
        virtual void configure (const libconfig::Setting &);
        
    private:
        
        /** lowest protocol to be included in the capture */
        Module*             _baseModule;
        
        /** prefix of the output file */
        std::string       _filePrefix;
        
        /** postfix of the output file */
        std::string       _filePostfix;
        
        /** pcap handle for writing */
        pcap_t*             _pcapHandle;
        
        /** pcap handle for output */
        pcap_dumper_t*      _pcapDumper;
        
        /** size of the current output file */
        std::streamsize     _currentFileSize;
        
        /** link type to be used in the output */
        std::streamsize     _maxFileSize;
        
        /** datalink type used for the output file */
        int _datalinkType;
        
        /** length of the packet to be saved from baseModule */
        u_int             _snapLength;
        
        /** number of packets to be dumped from each flow */
        u_int             _flowPackets;
        
        /** true if should use fixHeaders */
        bool              _fixHeaders;

        /** Pcap log is generated only if this is set to true */
        bool _outputEnabled;
};

#endif // __PCAP_OUTPUT_H__
