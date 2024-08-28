/*
 * FlowModule.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FLOW_MODULE_H__
#define __FLOW_MODULE_H__

#include <string>
#include <iostream>
#include <boost/function.hpp>
#include <cassert>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "modulemanager/ModuleManager.h"

#include "modules/gtpcontrol/PDPContext.h"
#include "captoolpacket/CaptoolPacket.h"
#include "filemanager/FileGenerator.h"

#include "modules/gtpcontrol/GTPControl.h"

#include "flow/FlowID.h"

#include "flow/Flow.h"
#include "FlowList.h"

using std::string;

class DirectionUnknownException
{
};

namespace captool {

/**
 * Template for modules producing flow information.
 * @note FLowType is expected to have a ''Ptr'' member (e.g., boost::shared_ptr<FlowType>)
 *
 * @par %Module configuration -- global options only
 * @code
 *        flow:
 *        {
 *            connections = (
 *                            ("default", "dispatcher")       // has default connection only
 *            );
 *
 *            baseModule = "ip2";                             // the lowest level module whose headers are already included when counting total packet length
 *            flowTimeout = 120;                              // 0: never; default: 0
 *            filePrefix = "out/flows";                       // prefix of output files
 *            filePostfix = ".txt";                           // postfix of output files (including extension)
 *            maxFileSize = 0;                                // maximum output file size; 0 = inf
 *            printHints = true;                              // specifies whether the list of classification hints should be printed in the flow log or not (default = false)
 *            storebytes = 0;                                 // store first this many uplink+downlink bytes per flow in the flowlog (default = 0)
 *            detailedStatistics = false;                     // set to true in order to generate detailed packet size and packet IAT statistics in the flow log (default = false)
 *            outputEnabled = true;                           // enables/disables flow log output
 *            firstFlowModule = "p2pheuristics";              // the name of the first flow processing module which processes flows after they are timed out
 *                                                            // (similarly to the activeModule - being the main entry point for packet processing - the module specified here is the main entry point for flow processing)
 *        };
 * @endcode
 */
template<class FlowType, class FlowComparator>
class FlowModule : public captool::Module, public captool::FileGenerator
{
    
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit FlowModule(std::string name);
        
        /**
         * Destructor.
         */    
        virtual ~FlowModule();
        
        // inherited from FileGenerator
        void openNewFiles();
        
    protected:
        
        virtual void initialize(libconfig::Config *);
        
        virtual void configure (const libconfig::Setting &);
        
        /** 
         * Perform optional pre-processing tasks before updating flow statistics 
         * (e.g. swap endpoints in flowid, drop packets with unknown direction)
         *
         * @param packet pointer to the processed CaptoolPacket object
         * @param flowid safe pointer the FlowID object of the processed packet
         */
        virtual void preprocess(CaptoolPacket * packet, FlowID::Ptr flowid) throw(DirectionUnknownException);
        
        /**
         * Perform optional post-processing tasks after updating flow statistics
         * (e.g. update user and equipment IDs within flow)
         *
         * @param packet pointer to the processed CaptoolPacket object
         * @param flow safe pointer the Flow object to which the processed packet belongs to
         */
        virtual void postprocess(CaptoolPacket * packet, Flow::Ptr flow);
        
        /** 
         * Determine whether the processed packet should be consider as uplink or downlink within the flow
         * Note: the meaning of uplink and downlink is different for the FlowOutput and FlowOutputStrict modules
         * 
         * @param packet pointer to the processed CaptoolPacket object
         * @param flow safe pointer the Flow object to which the processed packet belongs to
         */
        virtual bool isUplink(CaptoolPacket * packet, Flow::Ptr flow) = 0;
        
        /**
         * Cleans up timed out flows from the map. Timeout parameter is set by the constructor.
         * Giving 0 as parameter forces all flows to time out.
         *
         * @param time pointer to a timeval structure representing current time
         */
        void printFlowlog(const Flow *);

        /** lowest protocol in the stack to be counted into packets byte length. If null, the whole length is counted. */
        Module           *_baseModule;
        
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
        
        /** map type for mapping FlowID s to their Flow s */
        typedef FlowList<FlowType,FlowComparator>	MyFlowList;
        
        /** map mapping FlowID s to their Flow s */
        MyFlowList           _flows;
        
        /** If set to true, than collection of detailed packet statistics (size, IAT) is enabled */
        bool                 _detailedStatistics;
        
        /** number of bytes to store in the flowlog (total, in both directions) */
        size_t               storesize;
        
        /** Store range of bytes as a flow option string value */
        void storeBytes(FlowType &flow, const CaptoolPacket &packet, bool uplink);
        
        /** flow option name for stored uplink bytes */
        static std::string OPTION_UPLINK_BYTES;
        
        /** flow option name for stored downlink bytes */
        static std::string OPTION_DOWNLINK_BYTES;
        
        /** Flow log entries are printed only if this is set to true */
        bool _outputEnabled;

        /** Total number of bytes captured during the current period */
        u_int64_t _totalBytes;

        /** Total number of dropped bytes (due to unknown direction) during the current period */
        u_int64_t _droppedBytes;

    private:

        Module* process(CaptoolPacket * captoolPacket);
        
        void processFlow(const Flow *);

        /** true if classifications hints should be also printed in the flow log; false otherwise */
        bool _printHints;
        
        Module* _firstFlowModule;
};

template<class F, class C>
FlowModule<F,C>::FlowModule(std::string name)
    : Module(name),
      _baseModule(0),
      _currentFileSize(0),
      _maxFileSize(2 << 26),
      _flows(),
      _detailedStatistics(false),
      storesize(0),
      _outputEnabled(true),
      _totalBytes(0),
      _droppedBytes(0),
      _printHints(false),
      _firstFlowModule(0)
{
}

template<class F, class C>
FlowModule<F,C>::~FlowModule()
{
    _fileStream << "----------------------------------------" << std::endl;
    
    // flush all remaining flows
    boost::function<void (const F *)> f;
    f = std::bind1st(std::mem_fun(&FlowModule<F,C>::processFlow),this);
    _flows.cleanup(0, f);

    // close stream
    if (_fileStream.is_open())
    {
        _fileStream.flush();
        _fileStream.close();
    }
 
}

template<class F, class C>
void
FlowModule<F,C>::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")
            
    Module::initialize(config);
    
    const string mygroup = "captool.modules." + _name;
    string tmp;

    // get base module
    if (!config->lookupValue(mygroup + ".baseModule", tmp))
    {
        CAPTOOL_MODULE_LOG_WARNING("baseModule not set.")
    }
    else
    {
        _baseModule = ModuleManager::getInstance()->getModule(tmp);

        if (_baseModule == 0)
        {
            CAPTOOL_MODULE_LOG_WARNING("baseModule not found.")
        }
    }

    // get file prefix
    if (!config->lookupValue(mygroup + ".filePrefix", _filePrefix))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filePrefix not set.")
        exit(-1);
    }

    // get file postfix
    if (!config->lookupValue(mygroup + ".filePostfix", _filePostfix))
    {
        CAPTOOL_MODULE_LOG_SEVERE("filePrefix not set.")
        exit(-1);
    }
    
    if (!config->lookupValue(mygroup + ".detailedStatistics", _detailedStatistics))
    {
        CAPTOOL_MODULE_LOG_CONFIG("detailedStatistics not set, using default value (" << _detailedStatistics << ").")
    }

    openNewFiles();
    
    // set max file size
    if (!config->lookupValue(mygroup + ".maxFileSize", _maxFileSize))
    {
        CAPTOOL_MODULE_LOG_CONFIG("maxFileSize not set, using default value (" << _maxFileSize << ").")
    }
    
    ModuleManager::getInstance()->getFileManager()->registerFileGenerator(this);
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));
        
    // Get the first flow module (the entry point for processing flows after their timeout)
    if (config->lookupValue(mygroup + ".firstFlowModule", tmp))
    {
        _firstFlowModule = ModuleManager::getInstance()->getModule(tmp);
        if (_firstFlowModule == 0)
        {
            CAPTOOL_MODULE_LOG_SEVERE("cannot find flow module defined for " << tmp);
            exit(-1);
        }
    }
}

template<typename F, typename C>
void
FlowModule<F,C>::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    if (cfg.lookupValue("outputEnabled", _outputEnabled))
        CAPTOOL_MODULE_LOG_CONFIG("output " << (_outputEnabled ? "enabled" : "disabled") << ".")
    
    unsigned int flowtimeout;
    if (cfg.lookupValue("flowTimeout", flowtimeout))
    {
        _flows.setTimeout(flowtimeout);
        CAPTOOL_MODULE_LOG_CONFIG("using flow timeout " << flowtimeout << "s")
    }
    
    if (cfg.lookupValue("printHints", _printHints))
        CAPTOOL_MODULE_LOG_CONFIG("printHints " << (_printHints ? "enabled" : "disabled") << ".");

    if (cfg.lookupValue("storebytes", storesize))
    {
        if (storesize)
            CAPTOOL_MODULE_LOG_CONFIG("storing first " << storesize << " uplink+downlink bytes for each flow")
        else
            CAPTOOL_MODULE_LOG_CONFIG("not storing any bytes")
    }
}

template<class F, class C>
void
FlowModule<F,C>::preprocess(CaptoolPacket *, FlowID::Ptr)
throw (DirectionUnknownException)
{}

template<class F, class C>
void
FlowModule<F,C>::postprocess(CaptoolPacket *, Flow::Ptr)
{}

template<class F, class C>
Module*
FlowModule<F,C>::process(CaptoolPacket* captoolPacket)
{
    if (captoolPacket == 0) return 0;

    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    FlowID::Ptr fid = FlowID::Ptr(new FlowID(captoolPacket->getFlowID()));

    if (!fid.get() || !fid->isSet())
    {
        return _outDefault;
    }

    // get length of packet from baseModule
    u_int length = captoolPacket->getSegmentsTotalLength(_baseModule);
    _totalBytes += length;

    // clean up flows
    {
        boost::function<void (const Flow *)> f = std::bind1st(std::mem_fun(&FlowModule::processFlow),this);
        _flows.cleanup( & (captoolPacket->getPcapHeader()->ts), f );
    }

    // pre-processing by child class
    try 
    {
        preprocess(captoolPacket, fid);
    }
    catch (DirectionUnknownException)
    {
        _droppedBytes += length;
        CAPTOOL_MODULE_LOG_INFO("Direction of packet no. " << captoolPacket->getPacketNumber() << " cannot be determined (e.g. GSN IPs or gateway macs not yet known). Dropping packet")
        return 0;
    }

    Flow::Ptr flow = _flows.get(fid);
    
    // new flow
    if (! flow)
    {
        flow = Flow::Ptr(new Flow(fid));
        if (_detailedStatistics) flow->enableDetailedStatistics();
    }
    
    if (flow)
    {
        bool ul = isUplink(captoolPacket, flow);
        flow->packet(&(captoolPacket->getPcapHeader()->ts), ul, length);
        captoolPacket->setFlowNumber(flow->getPacketsNumber());
        captoolPacket->setFlow(flow);
        
        if (storesize) storeBytes(*flow, *captoolPacket, ul);
    }
    
    _flows.moveToEnd(flow);
    
    // Optional post-processing by child class
    postprocess(captoolPacket, flow);

    return _outDefault;
}

template<class F, class C>
void
FlowModule<F,C>::processFlow(const Flow * flow)
{
    // Execute flow modules
    Module* currentModule = _firstFlowModule;
    while (currentModule)
    {
        currentModule = currentModule->process(flow);
    }

    printFlowlog(flow);
}

template<class F, class C>
void
FlowModule<F,C>::printFlowlog(const Flow * flow)
{
    if (flow == 0 || !_outputEnabled) return;
    
    std::streampos pos = _fileStream.tellp();
    
    // flush
    _fileStream << *(F*) flow;
    if (_printHints)
    {
        _fileStream << *(Hintable*)flow;
    }
    flow->printOptions(&_fileStream);
    _fileStream << "\n";
    
    _currentFileSize += _fileStream.tellp() - pos;
    
    if ( (_maxFileSize > 0) && (_currentFileSize >= _maxFileSize) )
    {
        ModuleManager::getInstance()->getFileManager()->fileSizeReached();
    }
}

template<class F, class C>
void
FlowModule<F,C>::openNewFiles()
{
    if (!_outputEnabled) 
    {
        return;
    }

    ModuleManager::getInstance()->getFileManager()->openNewFile(_fileStream, _filePrefix, _filePostfix);
    _currentFileSize = 0;
}

template<class F, class C>
std::string FlowModule<F,C>::OPTION_UPLINK_BYTES = "uplink-bytes";

template<class F, class C>
std::string FlowModule<F,C>::OPTION_DOWNLINK_BYTES = "downlink-bytes";

template<class F, class C>
void
FlowModule<F,C>::storeBytes(F &flow, const CaptoolPacket &pkt, bool uplink)
{
    // NB: this is 2x the size (2 chars per byte)
    size_t currcnt = flow.getOption(OPTION_UPLINK_BYTES).length() + flow.getOption(OPTION_DOWNLINK_BYTES).length();
    
    CAPTOOL_MODULE_LOG_FINER("storeBytes  flow " << (size_t) flow.getID() << "  currcnt " << currcnt << "  storesize " << storesize);
    
    if (currcnt >= 2 * storesize)
        return;
    
    size_t pktlen;
    const unsigned char *payload = pkt.getPayload(&pktlen);
    
    size_t len = std::min(storesize - currcnt / 2, pktlen);
    
    if (len == 0)
        return;
    
    static const char hexval[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    std::ostringstream buf;
    
    for (size_t pos = 0; pos < len; ++pos)
        buf << hexval[(payload[pos] >> 4) & 0xf] << hexval[payload[pos] & 0x0f];
    
    static const std::string nullsep = "";
    
    flow.registerOption(uplink ? OPTION_UPLINK_BYTES : OPTION_DOWNLINK_BYTES,
                        buf.str(),
                        true,
                        true,
                        nullsep);
    
    CAPTOOL_MODULE_LOG_FINER("  stored " << len << " " << buf.str());
    CAPTOOL_MODULE_LOG_FINER("  now " << (uplink ? OPTION_UPLINK_BYTES : OPTION_DOWNLINK_BYTES)
                             << " " << flow.getOption(uplink ? OPTION_UPLINK_BYTES : OPTION_DOWNLINK_BYTES).length() 
                             << " " << flow.getOption(uplink ? OPTION_UPLINK_BYTES : OPTION_DOWNLINK_BYTES));
}

} // namespace captool
#endif // __FLOW_MODULE_H__
