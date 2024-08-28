/*
 * FlowPacketConverter.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOWPACKET_CONVERTER_H__
#define __FLOWPACKET_CONVERTER_H__

#include <string>

/**
 * Class for converting binary FlowPacket output to readable format.
 */
class FlowPacketConverter {
    
    public:
        
        /**
         * Constructor.
         *
         * @param inputFileName name of the input file
         * @param outputFileName name of the output file
         */
        FlowPacketConverter(std::string inputFileName, std::string outputFileName);
        
        /**
         * Runs the conversion
         */
        void run();
        
    private:
        
        /** name of the input file */
        std::string _inputFileName;

        /** name of the output file */
        std::string _outputFileName;
};

/**
 * Main function. Initializes and starts Captool.
 *
 * @param argc number of arguments (including executable name)
 * @param argv input arguments
 *
 * @return the exit code of the program
 */
int main(int argc, char* argv[]);

#endif // __FLOWPACKET_CONVERTER_H__
