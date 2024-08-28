/*
 * FileManager.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <ctime>
#include <iostream>
#include <fstream>
#include <sys/vfs.h>
#include <cstdlib>
#include <cassert>
#include <sys/stat.h>
#include <cerrno>
#include <sstream>

#include "modulemanager/activemodule/ActiveModule.h"
#include "modulemanager/ModuleManager.h"

#include "FileManager.h"

#include "util/log.h"

namespace captool {

FileManager::FileManager()
    : _splitFiles(true),
      _fileIndex(0),
      outdir("."),
      _finalizing(false)
{

    /* generate datetime */
        
    time_t time;
    std::time(&time);
    
    struct tm *tm = localtime(&time);
    
    std::stringstream s;
    
    s << (1900 + tm->tm_year);
    s.fill('0');
    s.width(2);
    s << (1 + tm->tm_mon);
    s.width(2);
    s << tm->tm_mday;
    s.width(2);
    s << tm->tm_hour;
    s.width(2);
    s << tm->tm_min;
    s.width(2);
    s << tm->tm_sec;
    
    _startupTime = s.str();
    
    s << "-";
    s.fill('0');
    s.width(6);
    s << _fileIndex;
    
    _fileSuffix = "-" + s.str();
    
}

void
FileManager::initialize(libconfig::Config* config)
{
    assert(config != 0);

    CAPTOOL_LOG_FINE("FileManager initializing.")
    
    try {
        configure(config->lookup("captool.fileManager"));
    } catch (libconfig::SettingNotFoundException) {
        CAPTOOL_LOG_WARNING("No configuration group \"captool.fileManager\" is found;  using default FileManager settings.")
    }
}

void
FileManager::configure (const libconfig::Setting & config)
{
    /* Checking new output dir is done to prevent accidental killing of Captool
     * (openNewFile() would call stop if output file can not be opened).
     * Therefore output dir is not changed if the new path seems not OK.
     */
    std::string newoutdir;
    if (config.lookupValue("outputDirectory", newoutdir))
    {
        bool OK = true;
        std::ostringstream msg ("FileManager: ");
        struct stat stats;
        if (stat(newoutdir.c_str(), &stats) == -1)
        {
            OK = false;
            if (errno == ENOENT)
            {
                if (mkdir(newoutdir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == 0)
                    OK = true;
                else
                    msg << "output directory \"" << newoutdir << "\" does not exist and can not be created";
            }
            else
                msg << "problem checking output directory \"" << newoutdir << "\" (errno " << errno << ")";
        }
        else if (! S_ISDIR(stats.st_mode))
        {
            OK = false;
            msg << "output path \"" << outdir << "\" is not a directory";
        }
        
        if (OK)
        {
            outdir = newoutdir;
            CAPTOOL_LOG_CONFIG(msg.str() << "using output path \"" << outdir << "\".")
        }
        else
        {
            CAPTOOL_LOG_SEVERE(msg.str() << ";  output directory not changed.")
        }
    }
    
    if (config.lookupValue("splitFiles", _splitFiles))
    {
        CAPTOOL_LOG_CONFIG((_splitFiles ? "" : "not ") << "splitting output files")
    }
}    
    
FileManager::~FileManager()
{
}

void
FileManager::registerFileGenerator(FileGenerator *generator)
{
    _fileGenerators.insert(generator);
}

void
FileManager::fileSizeReached()
{
    // skip warnings during finalization
    if (_finalizing)
    {
        return;
    }
    
    struct statfs stats;
    statfs(outdir.c_str(), &stats);
    if ((size_t) stats.f_bavail * stats.f_bsize < MINSPACE)
    {
        CAPTOOL_LOG_SEVERE("Stopping Captool:  not enough disk space to open new files (<" << MINSPACE << ").")
        _finalizing = true;
        ModuleManager::getInstance()->getActiveModule()->stop();
    }
    else
    {
        // no splitting
        if (!_splitFiles)
        {
            return;
        }

        // update new file suffix
        ++_fileIndex;

        std::stringstream s;
        s << "-";
        s << _startupTime;
        s << "-";
        s.fill('0');
        s.width(6);
        s << _fileIndex;
        _fileSuffix = s.str();

        for (FileGeneratorSet::const_iterator iter(_fileGenerators.begin()), end(_fileGenerators.end()); iter != end; ++iter)
        {
            (*iter)->openNewFiles();
        }
    }
}

void 
FileManager::openNewFile(std::ofstream& filestream, const std::string prefix, const std::string postfix) const 
{
    if (filestream.is_open()) filestream.close();
    
    std::string tmp(outdir);
    if (tmp.size())
        tmp.append("/");
    tmp.append(prefix);
    if (_splitFiles) tmp.append(_fileSuffix);
    tmp.append(postfix);
    
    // open file
    filestream.open(tmp.c_str(), std::ios::out | std::ios::ate);
    if (!filestream.is_open())
    {
        CAPTOOL_LOG_SEVERE("Unable to open output file \"" << tmp << "\";  exiting Captool.")
        ModuleManager::getInstance()->getActiveModule()->stop();
    }
}

void
FileManager::openNewFile(pcap_dumper_t** dumper, const std::string prefix, const std::string postfix, pcap_t* handle) const
{
    if (*dumper != 0) pcap_dump_close(*dumper);
    
    std::string tmp(outdir);
    if (tmp.size())
        tmp.append("/");
    tmp.append(prefix);
    if (_splitFiles) tmp.append(_fileSuffix);
    tmp.append(postfix);
    
    // open output writer
    *dumper = pcap_dump_open(handle, tmp.c_str());

    if (*dumper == 0)
    {
        CAPTOOL_LOG_SEVERE("Unable to open pcap dump file (" << pcap_geterr(handle) << ").")
        ModuleManager::getInstance()->getActiveModule()->stop();
    }
}

void 
FileManager::time(const struct timeval *)
{
    if (!_splitFiles) return;
    fileSizeReached();
}

} // namespace captool
