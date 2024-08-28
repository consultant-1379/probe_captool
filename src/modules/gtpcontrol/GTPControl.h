/*
 * GTPControl.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __GTP_CONTROL_H__
#define __GTP_CONTROL_H__

#include <cassert>
#include <string>
#include <fstream>
#include <ostream>
#include <tr1/unordered_map>
#include <boost/pool/pool_alloc.hpp>

#include "libconfig.h++"

#include <ctime>

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"


#include "modules/ip/IP.h"

#include "ip/IPAddress.h"

#include "userid/IMSI.h"

#include "filemanager/FileGenerator.h"

#include "PDPConnections.h"
#include "PDPConnection.h"
#include "PDPConnectionEquals.h"
#include "PDPConnectionHasher.h"
#include "PDPContext.h"

#include "GTPInformationElements.h"

#include "modules/filter/SamplingFilterProcessor.h"

#include "gtp.h"

/**
 * Module for parsing GTP-C messages.
 *
 * @note SGSN user data tunnelling (after SGSN context updates) is discarded
 * @note PDP Updates to teid 0 are discarded (used when moving to v1, and during recovery)
 * @note in the UDP module both source and destination ports are checked (see Maxis)
 * @note only one transaction can be active between any GSN pairs
 * @note if either GSN wants to delete a PDP context, that context is deleted regardless of the response
 * @note end user and SGSN address types are IPv4, and are not checked
 * @note in SGSN Updates, primary PDP comes first and all secondaries follow before another primary
 *
 * @par %Module configuration
 * @code
 * gtpc:
 * {
 *   type = "GTPControl";
 *   gsnIPModule = "ip";      // which IP module to ask for packet's gsn ip address
 *   filePrefix = "out/pdp";  // prefix of PDP output files
 *   filePostfix = ".txt";    // postfix of PDP output files (including extension)
 *   maxFileSize = 50000000;  // maximum output file size; 0 = inf.
 *   pdpTimeout = 36000;      // Length of inactivity period [sec] after which a PDP context is purged (0 means no timeouts at all)
 *   samplingRatio = 0.5;     // Specifies the ratio of subscribers whose traffic will pass via the IP filter in the kernel module
                              // This filter is controled by the GTPControl module.
 * };
 *
 * securityManager:
 * {
 *   anonymize = true;                  // Anonymize IMSI-s, IMEI-s, and IP addresses; default = false
 *   paranoid = false;                  // Allow using futher obfuscation by hashing IMSIs from 15 digits to 13 digits (at the expense of possible collisions!); default = false
 *   imsiKeyLocation = "conf/imsi.key"; // location of IMSI encryption key
 * };
 * @endcode
 */
class GTPControl : public captool::Module, public captool::FileGenerator
{
    public:

    	enum NodeFunctionality {
            UNDEFINED,
            SGSN,
            GGSN
	    };
        
        /**
         * Returns the associated PDPContext of the given PDPConnection
         * and updates last activity timestamp of the corresponding PDP context.
         *
         * @note used by GTPUser module to find the IMSI associated with a user PDU.
         *
         * @param connection the PDPConnection of the packet
         * @param timestamp, the timestamp corresponding to the last user space activity from this IP address
         *
         * @return the associated PDPContext
         */
        const PDPContext *updatePDPContext(PDPConnection *connection, const struct timeval timestamp);
	
        /**
         * Returns the associated PDPContext of the given user IP
         * and updates last activity timestamp of the corresponding PDP context.
         *
         * @note used by FlowOutput modules to find the IMSI associated with the user's IP.
         *
         * @param IP the IP address of the user
         * @param timestamp, the timestamp corresponding to the last user space activity from this IP address
         *
         * @return the associated PDPContext
         */
        const PDPContext * updatePDPContext(const IPAddress::Ptr & ip, const struct timeval timestamp);
        
        /**
         * Returns node functionality based on the given node IP.
         *
         * @note used by GTPUser to determine direction of packets.
         *
         * @param IP the IP address of the node
         *
         * @return the functionality of the node
        */
        NodeFunctionality getNodeFunctionality(const IPAddress::Ptr & ip) const;
	
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit GTPControl(std::string name);

        /**
         * Destructor.
         */    
        ~GTPControl();

        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);

        // inherited from Module
        void getStatus(std::ostream *s, u_long runtime, u_int period);

        // inherited from Module
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);

        // inherited from FileGenerator
        void openNewFiles();
        
    protected:

        void initialize(libconfig::Config* config);
        
        virtual void configure (const libconfig::Setting &);
        
    private:
        
        /**
         * Parse TBCD encoded IMSI string.
         *
         * @param ie GTP-C Information Element containing the encoded IMSI (8 octets)
         */
        IMSI::Ptr parseIMSI (u_int8_t * const & ie) const;
        
        /**
         * Parse TBCD encoded IMSI string.
         *
         * @param ie GTP-C Information Element containing the encoded IMSI (8 octets)
         */
        IMEISV::Ptr parseIMEISV (u_int8_t * const & ie) const;
        
        /**
         * Handles Create PDP Request messages for primary PDP contexts
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
        void handleCreatePDPRequestPrimary(captool::CaptoolPacket *captoolPacket, gtp_header* gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles Create PDP Request messages for secondary PDP contexts
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
        void handleCreatePDPRequestSecondary(captool::CaptoolPacket *captoolPacket, gtp_header* gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles Create PDP Response messages
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
       void handleCreatePDPResponse(captool::CaptoolPacket *captoolPacket, gtp_header* gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles Update PDP Request messages
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
        void handleUpdatePDPRequest(captool::CaptoolPacket *captoolPacket, gtp_header* gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles Update PDP Request messages sent for version changes
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
        void handleUpdatePDPRequestVersion(captool::CaptoolPacket *captoolPacket, gtp_header* gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles Update PDP Response messages
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
       void handleUpdatePDPResponse(captool::CaptoolPacket *captoolPacket, gtp_header* gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles Delete PDP Request messages
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
        void handleDeletePDPRequest(captool::CaptoolPacket *captoolPacket, gtp_header* gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles Delete PDP Response messages
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
        void handleDeletePDPResponse(captool::CaptoolPacket *captoolPacket, gtp_header* gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles SGSN Context Request messages
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
        void handleSGSNRequest(captool::CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles SGSN Context Response messages
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
       void handleSGSNResponse(captool::CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Handles SGSN Context Acknowledgement messages
         *
         * @param captoolPacket the CaptoolPacket being processed
         * @param gtp pointer to the gtp header of the packet
         * @param ie pointer to first IE
         * @param payloadLength total length of the remaining IEs
         */
        void handleSGSNAcknowledgement(captool::CaptoolPacket *captoolPacket, gtp_header *gtp, u_int8_t *ie, u_int payloadLength);

        /**
         * Parses the next extension header of the gtp header.
         *
         * @param begin pointer to the beginning of this extension header
         * @param length pointer where the length of this extension header is to be returned
         *
         * @return true if there is another extension header following this one
         */
        bool parseNextExt(const u_int8_t* begin, u_int8_t* length);
        
        /**
         * Skips the current information element in the GTP-C message
         *
         * @param ie pointer to the current information element
         * @param length remaining length of the complete packet
         *
         * @return pointer to the next information element,
         * or 0 if there are no more IEs, or -1 on error
         */
        u_int8_t *nextInformationElement(u_int8_t *ie, u_int *length);

        /**
         * Deletes the given PDPContext and removes it from both PDPConnection maps.
         * Also puts the context into the output file
         *
         *
         * @param context the PDPContext to be deleted
         * @param write if true the context is written to the output file
         * @param timestamp the current time. If 0 given, no delete timestamp is written
         *
         * @note the output format is : createdAt|deletedAt|IMSI|userIP
         */
        void deletePDPContext(PDPContext *context, bool write, const struct timeval *timestamp);
	
    	/**
    	 * Associates node IP with node functionality
    	 *
    	 * @note this mapping is used by GTPUser to identify direction of user plane packets
    	 */
    	 void registerNodeFunctionality(const IPAddress::Ptr & ip, NodeFunctionality functionality);
        
        /** 
         * Parse User Location Information Element. 
         *
         * @param ie a pointer to the information element
         * @return a textual description of location information or empty string in case of error
         */
        string parseUserLocationIE(const u_int8_t * ie);

        /** the IP module that should be requested for the GSN IP Address of the current packet */
        IP *_gsnIPModule;
        
        /** storage of information element names and lengths */
        GTPInformationElements _ies;

        /** pair type for storing PDPConnection and PDPContext pairs */
        typedef std::pair< PDPConnection *, PDPContext *> PDPContextMapPair;
        
        /** map type for mapping PDPConnection s to PDPContext s */
        typedef std::tr1::unordered_map <PDPConnection *, PDPContext *, PDPConnectionHasher, PDPConnectionEquals, boost::fast_pool_allocator<PDPContextMapPair> > PDPContextMap;
        
        /** map for mapping control PDPConnection s to their PDPContext s */
        PDPContextMap _pdpControlMap;

        /** map for mapping user PDPConnection s to their PDPContext s */
        PDPContextMap _pdpDataMap;

        /** pair type for storing IP and PDPContext pairs */
        typedef std::pair < IPAddress::Ptr, PDPContext *> IPMapPair;
        
        /** map type for mapping IP s to PDPContext s */
        typedef std::tr1::unordered_map <
                                         IPAddress::Ptr, 
                                         PDPContext *, 
                                         std::tr1::hash<const IPAddress::Ptr>, 
                                         std::equal_to<const IPAddress::Ptr>,
                                         boost::fast_pool_allocator<PDPContextMapPair> 
                                        > IPMap;
        
        /** map for mapping control PDPConnection s to their PDPContext s */
        IPMap _ipMap;
        
        /** pair type for storing IP and NodeFunctionality pairs */
        typedef std::pair <IPAddress::Ptr,NodeFunctionality> GatewayIPMapPair;

        /** map type for mapping IP addresses of network devices to their functionality (SGSN or GGSN). */
        typedef std::tr1::unordered_map <
                                         IPAddress::Ptr,
                                         NodeFunctionality,
                                         std::tr1::hash<const IPAddress::Ptr>,
                                         std::equal_to<const IPAddress::Ptr>,
                                         boost::fast_pool_allocator<GatewayIPMapPair>
                                        > GatewayIPMap;
	
        /** maps IP addresses of network devices to a boolean characterizing their functionality. */
        GatewayIPMap _gatewayIPMap;

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
        
        /** true if output is generated */
        bool              _output;
        
        /** true if subscriber IDs (e.g. IMSI, IMEI) should be anonimized */
        bool              _anonymize;

        /** allow setting futher obfuscation by hashing IMSIs from 15 digits to 13 digits (at the expense of possible collisions!) */
        bool              _anonymizeParanoid;
        
        /** imsi encryption key */
        std::string            _imsiKey;

        /** Timestamp of the last control or data plane packet */
        std::time_t            _lastTimestamp;

        /** The length of the inactive period (in seconds) after which a PDP is deleted */
        std::time_t            _pdpTimeout;

        /** The IMSI filter used to control per IMSI statistical sampling in the kernel */
        SamplingFilterProcessor *     _imsifilter;

        /** GTP type for Create PDP Request */
        static const u_int8_t MESSAGE_TYPE_CREATE_PDP_REQUEST = 16;
        
        /** GTP type for Create PDP Response */
        static const u_int8_t MESSAGE_TYPE_CREATE_PDP_RESPONSE = 17;
        
        /** GTP type for Update PDP Request */
        static const u_int8_t MESSAGE_TYPE_UPDATE_PDP_REQUEST = 18;
        
        /** GTP type for Update PDP Response */
        static const u_int8_t MESSAGE_TYPE_UPDATE_PDP_RESPONSE = 19;
        
        /** GTP type for Delete PDP Request */
        static const u_int8_t MESSAGE_TYPE_DELETE_PDP_REQUEST = 20;
        
        /** GTP type for Delete PDP Response */
        static const u_int8_t MESSAGE_TYPE_DELETE_PDP_RESPONSE = 21;
        
        /** GTP type for SGSN Request */
        static const u_int8_t MESSAGE_TYPE_SGSN_REQUEST = 50;
        
        /** GTP type for SGSN Response */
        static const u_int8_t MESSAGE_TYPE_SGSN_RESPONSE = 51;
        
        /** GTP type for SGSN Acknowledgement */
        static const u_int8_t MESSAGE_TYPE_SGSN_ACKNOWLEDGEMENT = 52;

        /** IE type for Cause */
        static const u_int8_t IE_CAUSE = 1;

        /** IE type for IMSI */
        static const u_int8_t IE_IMSI = 2;

        /** IE type for user TEID */
        static const u_int8_t IE_DATA_TEID = 16;

        /** IE type for control TEID */
        static const u_int8_t IE_CONTROL_TEID = 17;

        /** IE type for NSAPI */
        static const u_int8_t IE_NSAPI = 20;

        /** IE type for user IP */
        static const u_int8_t IE_USER_IP = 128;

        /** IE type for PDP context */
        static const u_int8_t IE_PDP_CONTEXT = 130;
        
        /** IE type for Access Point Name */
        static const u_int8_t IE_APN = 131;

        /** IE type for GSN IP Address */
        static const u_int8_t IE_GSN_ADDRESS = 133;

        /** IE type for RAT type */
        static const u_int8_t IE_RAT_TYPE = 151;

        /** IE type for User Location Information */
        static const u_int8_t IE_USER_LOCATION = 152;

        /** IE type for IMEI(SV) */
        static const u_int8_t IE_IMEISV = 154;
                
};

inline const PDPContext *
GTPControl::updatePDPContext(PDPConnection *connection, const struct timeval timestamp)
{
    assert(connection != 0);
    
    PDPContextMap::const_iterator iter = _pdpDataMap.find(connection);
    
    if (iter == _pdpDataMap.end())
    {
        return 0;
    }
    else
    {
        iter->second->updateTimestamp(timestamp);
        _lastTimestamp = timestamp.tv_sec;
        return iter->second;
    }
    
}

inline const PDPContext *
GTPControl::updatePDPContext(const IPAddress::Ptr & ip, const struct timeval timestamp)
{
    assert(ip);
    
    IPMap::const_iterator iter = _ipMap.find(ip);
    
    if (iter == _ipMap.end())
    {
        return 0;
    }
    else
    {
        iter->second->updateTimestamp(timestamp);
        _lastTimestamp = timestamp.tv_sec;
        return iter->second;
    }
    
}

inline GTPControl::NodeFunctionality 
GTPControl::getNodeFunctionality(const IPAddress::Ptr & ip) 
const
{
    assert(ip);
    
    GatewayIPMap::const_iterator iter = _gatewayIPMap.find(ip);
    
    if (iter == _gatewayIPMap.end())
    {
        return GTPControl::UNDEFINED;
    }
    else
    {
        return iter->second;
    }
}


inline bool
GTPControl::parseNextExt(const u_int8_t* begin, u_int8_t* length)
{
    assert(begin != 0);
    assert(length > 0);

    *length = begin[0];
    return (begin[*length - 1] != 0);
}

#endif // __GTP_USER_H__
