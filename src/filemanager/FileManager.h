/*
 * FileManager.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FILE_MANAGER_H__
#define __FILE_MANAGER_H__

#include <string>
#include <sstream>
#include <set>
#include <pcap.h>
#include <ctime>
#include <libconfig.h++>

#include "FileGenerator.h"
#include "modulemanager/activemodule/ActiveModuleListener.h"
#include "util/Configurable.h"

namespace captool {

class FileGenerator;
class ModuleManager;

/**
 * Class managing FileGenerator instances.
 *
 * @par %Configuration
 * @code
 *   fileManager: {
 *           splitFiles = true;          // if true, output files are split and postfixed
 *           outputDirectory = "./out";  // path to output directory (relative or absolute)
 *   };
 * @endcode
 */
class FileManager : public ActiveModuleListener, public Configurable
{
    public:
        
        void initialize(libconfig::Config*);
        void configure (const libconfig::Setting &);
        
        /**
         * Registers a FileGenerator to the FileManager.
         *
         * @param generator the FileGenerator
         */
        void registerFileGenerator(FileGenerator *generator);
        
        /**
         * A FileGenerator should notify FileManager by calling this method if they reached their maximum file size.
         * If there is enough space on the disc, FileManager invokes the openNewFiles() method for all registered {FileGenerator}s.
         * If not, it stops the ActiveModule.
         */
        void fileSizeReached();
        
        /**
         * Opens a new file for the specified file stream.
         */
        void openNewFile(std::ofstream& filestream, const std::string prefix, const std::string postfix) const;
        
        /**
         * Opens a new file for pcap output. 
         * @todo better make a wrapper around libpcap functions
         */
        void openNewFile(pcap_dumper_t** dumper, const std::string prefix, const std::string postfix, pcap_t* handle) const;
        
        void time(const struct timeval *time);
        
    private:
        
        /**
         * Constructor.
         */
        FileManager();
        
        /**
         * Destructor.
         */
        ~FileManager();

        /** true if files should be split */
        bool        _splitFiles;
        
        /** string representation of the start time */
        std::string _startupTime;
        
        /** index of the currently open output files */
        u_int       _fileIndex;
        
        /** generated postfix for output files */
        std::string _fileSuffix;

        /** path to output directory */
        std::string outdir;
        
        /** set type for storing FileGenerator s */
        typedef std::set<FileGenerator *> FileGeneratorSet;
        
        /** set of registered FileGenerator s */
	FileGeneratorSet _fileGenerators;
        
        /** true if there is not enough disc space and ActiveModule is being stopped */
        bool        _finalizing;
        
        /** minimum free space expected on the disk when opening new files (in bytes) */
        static const size_t   MINSPACE = 1000000;
        
        friend class ModuleManager;
};

} // namespace captool

#endif // __FILE_MANAGER_H__
