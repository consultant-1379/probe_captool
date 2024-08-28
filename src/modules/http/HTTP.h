/*
 * HTTP.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __HTTP_H__
#define __HTTP_H__

#include <string>
#include <ostream>
#include <set>

#include <pcre.h>

#include "libconfig.h++"

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#include "classification/Signature.h"
#include "classification/ClassificationMetadata.h"
#include "classification/Classifier.h"

using std::string;

/**
 * Classification module handling HTTP headers.
 * @par %Module configuration
 * @code
 * http:
 * {
 *   type = "HTTP";
 * 
 *   connections = (
 *                   ("http", "dpi"),                   // output for HTTP packets
 *                   ("non-http", "dpi")                // output for 
 *                 );
 * 
 *   httpHeadersToPrint = "User-Agent Content-Type";    // print these HTTP headers (separated by spaces)
 *   printUrl = true;                                   // print request URL-s in flow log (default = false)
 *   printHttpMethod = false;                           // print HTTP GET/POST method (default = false)
 *   printStatusCode = false;                           // print status code (default = false)
 *   maxBodySize = 20;                                  // parse this many bytes from HTTP body in addition to the headers (default = 20 bytes)
 * };
 * @endcode
 *
 * securityManager:
 * {
 *   anonymize = true;  // Sensitive information (e.g. everything after ? in URL-s) is removed in output
 * };
 */
class HTTP : public captool::Module, public Classifier
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit HTTP(string name);
        
        /**
         * Destructor.
         */    
        ~HTTP();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
        // inherited from Module
        void describe(const captool::CaptoolPacket* captoolPacket, std::ostream *s);
        
    protected:
        
        void initialize(libconfig::Config* config);
        virtual void configure (const libconfig::Setting &);
        void registerSignature(unsigned blockId, const Signature * signature);

    private:
        
        /**
         * Returns true if the packet seems to be a HTTP request based on the beginning of the first line.
         * Intended as a prelimnary "low-cost" filter
         */
        bool seemsHttpRequest(const char * payload, u_int payloadLength);

        /**
         * Returns true if the packet seems to be a HTTP request based on the beginning of the first line.
         * Intended as a prelimnary "low-cost" filter
         */
        bool seemsHttpResponse(const char * payload, u_int payloadLength);

        /**
         * Perse HTTP message or ignore packet if this is not an HTTP message
         *
         * @return true if this was an HTTP message
         */
        bool parseHttpMessage(captool::CaptoolPacket * captoolPacket, Flow * flow);
        
        /**
         * Process HTTP header field (for application classification) and optionally tags a classification hint for the flow
         */        
        void processHttpHeaderField(string fieldName, string fieldValue, Flow * flow);

        /**
         * Process HTTP body
         *
         * @param payload pointer to the payload string
         * @param offset offset of HTTP body from payload start
         * @param flow pointer to the associated flow object
         * @param isResponse true if this is a HTTP response false if this is a HTTP request
         */
        void processHttpBody(const string * payload, size_t offset, Flow * flow, bool isResponse);
        
        void registerOption(Flow * flow, const string& optionName, const string& optionValue);
        
        /** Structure to bind a hint with the corresponding signature regexp */
        typedef struct {
            Hintable::Hint hint;
            pcre * regexp;
            bool capture; // True if the regexp is also intended to be used for capturing subpatterns
            string patternName; // The flow option name which should be used to register the captured pattern
        } HTTPSignature;
        
        /** Binds HTTP header name to the corresponding hint - signature pair(s) */
        typedef std::multimap<string, HTTPSignature> HTTPSignatureMap;
        
        HTTPSignatureMap signatureMap;
        
        /** When set to true, sensitive information (e.g. everything which cames after ? in a URL) should be removed from all printed HTTP fields */
        bool _anonymize;
        
        bool _printUrl;
        bool _printStatusCode;
        bool _printHttpMethod;
        
        /** Maximum number of bytes to check at the beginning of HTTP body */
        u_int maxParsedBodySize;
        
        /**
         * HTTP headers that should be processed in the current configuration.
         * This set can be changed by cofigure() but always will contain
         * elements of httpHeadersToProcessBase.
         */
        std::set<string> httpHeadersToProcess;
        
        /**
         * HTTP headers to be processed always.
         * These are headers requested by configuration.xml and therefore
         * should always be checked for traffic identification purposes.
         */
        std::set<string> httpHeadersToProcessBase;
        
        /** HTTP headers to print if encountered in a HTTP request or response. */
        std::set<string> httpHeadersToPrint;

        static const u_int MIN_HTTP_REQUEST_LENGTH = 16;
        static const u_int MIN_HTTP_RESPONSE_LENGTH = 17;
        
        static const string URL_OPTION_NAME;
        static const string STATUS_CODE_OPTION_NAME;
        static const string HTTP_METHOD_OPTION_NAME;
        static const string RESPONSE_BODY_NAME;
        static const string REQUEST_BODY_NAME;
        
        // Block ID for general HTTP hint
        unsigned _httpBlockId;
        // sig ID for general HTTP hint
        unsigned _httpSigId;
        
        /** connection to use for packets of HTTP flows */
        Module        *_outHttp;
        /** connection to use for packets of non-HTTP flows */
        Module        *_outNonHttp;
        
        /** name to be used in the configuration file for HTTP connection */
        static const std::string HTTP_CONNECTION_NAME;
        /** name to be used in the configuration file for non-HTTP connection */
        static const std::string NON_HTTP_CONNECTION_NAME;
};

#endif // __HTTP_H__
