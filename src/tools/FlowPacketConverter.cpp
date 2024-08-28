/*
 * FlowPacketConverter.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <arpa/inet.h>
#include <iomanip>
#include <libconfig.h++>
#include <cstring>
#include "ip/IPAddress.h"
#include "userid/TBCD.h"
#include "FlowPacketConverter.h"
#include "modules/flowpacket/FlowPacket.h"
#include "modules/flowpacket/FlowPacketFileStruct.h"
#include "util/log.h"
#include "classification/ClassificationMetadata.h"

FlowPacketConverter::FlowPacketConverter(std::string inputFileName, std::string outputFileName)
    : _inputFileName(inputFileName),
      _outputFileName(outputFileName)
{
}

void
FlowPacketConverter::run()
{
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();
    static const bool usecmd = cmd.isInitialized();
    const IdNameMapper & facetIDs = cmd.getFacetIdMapper();
    const IdNameMapper & focusIDs = cmd.getFocusIdMapper();
    
    std::ifstream input;
    input.open(_inputFileName.c_str(), std::ios::in | std::ios::binary);
    
    if (!input.good())
    {
        CAPTOOL_LOG_SEVERE("Error opening input file.")
        return;
    }
    
    try 
    {
        std::string magic;
        std::getline(input, magic, '\0');
        unsigned version;
        std::size_t pos = magic.find(FlowPacket::FILE_HEADER);
        std::istringstream ss (magic.substr(pos + FlowPacket::FILE_HEADER.size()));
        ss >> version;
        if (pos == magic.npos || version != FlowPacket::FILE_VERSION || ! input.good())
            throw 1;
    }
    catch (...)
    {
        CAPTOOL_LOG_SEVERE("Input file is not Captool packet log version " << FlowPacket::FILE_VERSION << ";  exiting")
        return;
    }
    
    std::ofstream output;
    output.open(_outputFileName.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);

    if (!output.good())
    {
        CAPTOOL_LOG_SEVERE("Error opening output file.")
        return;
    }
    
    struct FlowPacketFileStruct header;
    
    while (input.good())
    {
        if (input.read((char *) &header, sizeof(struct FlowPacketFileStruct)).eof())
        {
            if (input.gcount())
                CAPTOOL_LOG_WARNING("File is truncated;  exiting")
            break;
        }
        
        output << ntohl(header.secs) << "." << std::setfill('0') << std::setw(6) << ntohl(header.usecs) << "|";
        if (header.protocol == IPPROTO_UDP)
            output << "u";
        else if (header.protocol == IPPROTO_TCP)
            output <<  "t";
        else
            output << (int) header.protocol;
        output << "|"
               << IPAddress(ntohl(header.srcIP)) << "|" << ntohs(header.srcPort) << "|"
               << IPAddress(ntohl(header.dstIP)) << "|" << ntohs(header.dstPort) << "|"
               << ntohl(header.length) << "|"
               << header.direction << "|";
        bool defined = false;
        for (unsigned i = 0; i < TBCD::TBCD_STRING_LENGTH; ++i)
            if (header.user[i])
            {
                defined = true;
                break;
            }
        if (defined)
            output << TBCD(&header.user[0]);
        else
            output << "na";
        output << "|";
        defined = false;
        for (unsigned i = 0; i < TBCD::TBCD_STRING_LENGTH; ++i)
            if (header.equipment[i])
            {
                defined = true;
                break;
            }
        if (defined)
            output << TBCD(&header.equipment[0]);
        else
            output << "na";
        
        bool notfirst = false;
        for (int i = 0; i < header.facets; ++i)
        {
            if (i == 0)
            {
                output << "|";
                if (usecmd)
                    output << "tags={";
            }
            
            uint16_t val;
            if (input.read((char *) &val, sizeof(uint16_t)).eof())
            {
                CAPTOOL_LOG_WARNING("Tags truncated on last line;  exiting")
                break;
            }
            val = ntohs(val);
            
            if (usecmd)
            {
                if (val)
                {
                    std::string str = facetIDs.getName(i+1);
                    if (notfirst)
                        output << ",";
                    if (str != "na")
                        output << str;
                    else
                        output << (i + 1);
                    output << "=";
                    str = focusIDs.getName(val);
                    if (str != "na")
                        output << str;
                    else
                        output << val;
                    notfirst = true;
                }
            }
            else
                output << (i > 0 ? "," : "") << val;
            
            if (i == header.facets - 1 && usecmd)
                output << "}";
        }
        
        output << "\n";
    }
}

int main(int argc, char* argv[])
{
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();
    libconfig::Config cfg;
    switch (argc)
    {
      case 5:
        if (std::strcmp(argv[4], "encrypted"))
            goto err;
        try {
            cfg.getRoot()
                    .add("captool", libconfig::Setting::TypeGroup)
                    .add("securityManager", libconfig::Setting::TypeGroup)
                    .add("encryptedClassification", libconfig::Setting::TypeBoolean)
                = true;
        } catch (libconfig::SettingException & e) {
            CAPTOOL_LOG_SEVERE("Error reconstructing fake config: " << e.what())
        }
      case 4:
        try {
            if (! cfg.getRoot().exists("captool"))
                cfg.getRoot().add("captool", libconfig::Setting::TypeGroup);
            cfg.lookup("captool")
                    .add("classification", libconfig::Setting::TypeGroup)
                    .add("fileName", libconfig::Setting::TypeString)
                = argv[3];
            cmd.initialize(& cfg);
        } catch (libconfig::SettingException) {
            CAPTOOL_LOG_SEVERE("Error reconstructing classification tags from XML file;  will do without.")
        }
        if (!cmd.isInitialized())
            CAPTOOL_LOG_SEVERE("Error processing classification XML;  will not resolve facet/focus IDs.")
      case 3:
        FlowPacketConverter(std::string(argv[1]), std::string(argv[2])).run();
        break;
      default:
        goto err;
    }
    cmd.destroyInstance();
    return 0;
  err:
    std::cout << "Usage: " << argv[0] << " <input file> <output file> [<classification XML file> [\"encrypted\"]]\n\tadd word \"encrypted\" if decryption of classification XML is necessary (will ask for password)\n";
    return -1;
}
