/*
 * FlowPacket.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_PACKET_H__
#define __FLOW_PACKET_H__

#include <string>
#include <pcap.h>
#include <fstream>
#include <ostream>
#include <time.h>
#include <boost/pool/pool_alloc.hpp>

#include "modulemanager/Module.h"
#include "filemanager/FileGenerator.h"
#include "captoolpacket/CaptoolPacket.h"
#include "flow/FlowID.h"
#include "userid/ID.h"
#include "FlowPacketFileStruct.h"

/**
 * Module writing compressed header information for each packet.
 * These packet headers later can be processed by the @em flowpacketconverter
 * tool.
 * @par %Module configuration
 * @code
 * flowpacket:
 * {
 *   type = "FlowPacket";
 *
 *   connections = (
 *                  ("default", "dump")
 *                 );
 *
 *   baseModule = "ip2";          // the lowest level module whose headers are already included when counting total packet length
 *   filePrefix = "out/packets";  // prefix of output files
 *   filePostfix = ".bin";        // postfix of output files (including extension)
 *   maxFileSize = 0;             // maximum output file size; 0 = inf
 *   outputEnabled = false;       // enable / disable output
 * };
 *
 * securityManager:
 * {
 *   anonymize = true;            // Anonymize IP addresses in output; default = false
 * };
 * @endcode
 */
class FlowPacket : public captool::Module, public captool::FileGenerator
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit FlowPacket(std::string name);
        
        /**
         * Destructor.
         */    
        ~FlowPacket();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        // inherited from FileGenerator
        void openNewFiles();
        
        /** File magic header written at the start of each packet log file */
        static const std::string FILE_HEADER;
        
        /** Packet log file version number */
        static const unsigned FILE_VERSION;
        
    protected:

        void initialize(libconfig::Config *);
        
        virtual void configure (const libconfig::Setting &);
        
    private:
        
        /** lowest protocol in the stack to be counted into packets byte length. If null, the whole length is counted. */
        Module*              _baseModule;
        
        /** prefix of the output file */
        std::string       _filePrefix;
        
        /** postfix of the output file */
        std::string       _filePostfix;
        
        /** stream to write the output file to */
        std::ofstream     _fileStream;
        
        /** size of the current output file */
        std::streamsize   _currentFileSize;
        
        /** maximum size allowed for the output file */
        std::streamsize   _maxFileSize;

        /** buffer used for writing the binary output file */
        FlowPacketFileStruct _header;
        
        /** Packet header logs are printed only if this is set to true */
        bool                 _outputEnabled;
        
        /** true if subscriber IP address should be anonymized */
        bool              _anonymize;
                        
        /** Fill an ID field in #_header */
        void fillID (uint8_t * field, ID::Ptr const & id);
};

#endif // __FLOW_PACKET_H__
