/*
 * HTTP.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <string>
#include <cctype>
#include <pcre.h>
#include <cstdlib> // free()

#include "modulemanager/ModuleManager.h"
#include "flow/Flow.h"
#include "HTTP.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(HTTP)

const string HTTP::STATUS_CODE_OPTION_NAME = string("Status");
const string HTTP::HTTP_METHOD_OPTION_NAME = string("Method");
const string HTTP::URL_OPTION_NAME = string("URL");
const string HTTP::RESPONSE_BODY_NAME = string("http-response-body");
const string HTTP::REQUEST_BODY_NAME = string("http-request-body");

const string HTTP::HTTP_CONNECTION_NAME("http");
const string HTTP::NON_HTTP_CONNECTION_NAME("non-http");


HTTP::HTTP(string name)
    : Module(name),
      _anonymize(false),
      _printUrl(false),
      _printStatusCode(false),
      _printHttpMethod(false),
      maxParsedBodySize(20),
      _httpBlockId(0),
      _httpSigId(0)
{
}

HTTP::~HTTP()
{
    for (HTTPSignatureMap::const_iterator i = signatureMap.begin(); i != signatureMap.end(); ++i)
        free(i->second.regexp);
}

void
HTTP::initialize(libconfig::Config* config)
{
    assert(config != 0);
    
    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    // Register all HTTP signatures
    // Should come _before_ parsing httpHeadersToProcess setting
    registerSignatures();
    
    if (_httpBlockId == 0 || _httpSigId == 0)
    {
        CAPTOOL_MODULE_LOG_SEVERE("Generic HTTP block not defined in classification.xml")
        exit(-1);
    }
    
    // Lookup whether sensitive information (e.g. everything which cames after ? in a URL) should be removed from all printed HTTP fields
    if (!config->lookupValue("captool.securityManager.anonymize", _anonymize))
    {
        CAPTOOL_MODULE_LOG_WARNING("securityManager.anonymize not set, sensitive data will not be removed from printed HTTP fields.")
    }

    const string mygroup = "captool.modules." + _name;
    
    if (config->exists(mygroup))
        configure(config->lookup(mygroup));

    /* configure connections */
    libconfig::Setting& connectionSettings = config->lookup(mygroup + ".connections");
    
    for (int i=0; i<connectionSettings.getLength(); ++i)
    {
        libconfig::Setting& connection = connectionSettings[i];
        
        if (connection.getType() != libconfig::Setting::TypeList)
        {
            CAPTOOL_MODULE_LOG_SEVERE(i << "th connection setting is not a list")
            exit(-1);
        }

        if (connection.getLength() != 2)
        {
            CAPTOOL_MODULE_LOG_SEVERE("list no. " << i << " does not have a length of 2")
            exit(-1);
        }

        // skip default
        if (connection[0].getType() == libconfig::Setting::TypeString && Module::DEFAULT_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            continue;
        }
        
        // check list
        if (connection[0].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("firt element in list no. " << i << " is not a string.")
            exit(-1);
        }
        
        if (connection[1].getType() != libconfig::Setting::TypeString)
        {
            CAPTOOL_MODULE_LOG_SEVERE("second element in list no. " << i << " is not a string.")
            exit(-1);
        }
        
        if (HTTP_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outHttp = ModuleManager::getInstance()->getModule(moduleName);
            if (_outHttp == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        if (NON_HTTP_CONNECTION_NAME.compare((const char *)connection[0]) == 0)
        {
            string moduleName = connection[1];
            _outNonHttp = ModuleManager::getInstance()->getModule(moduleName);
            if (_outNonHttp == 0)
            {
                CAPTOOL_MODULE_LOG_SEVERE("cannot find module defined for " << moduleName);
                exit(-1);
            }
            continue;
        }

        CAPTOOL_MODULE_LOG_SEVERE("connection name must be http or non-http (or default)");
        exit(-1);
    }
}

void
HTTP::configure (const libconfig::Setting & cfg)
{
    if (! cfg.isGroup() || _name.compare(cfg.getName()))
        return;
    
    std::string parts = "";
    
#define CHECK_PARTS(setting, variable, text) \
    if (cfg.lookupValue((setting), (variable)) && (variable)) \
    { \
        if (parts.length()) \
            parts += ", "; \
        parts += (text); \
    }
        
    CHECK_PARTS ("printUrl", _printUrl, "URL")
    CHECK_PARTS ("printHttpMethod", _printHttpMethod, "HTTP method")
    CHECK_PARTS ("printStatusCode", _printStatusCode, "status code")

#undef CHECK_PARTS
    
    if (parts.length())
        CAPTOOL_MODULE_LOG_CONFIG("printing " << parts << " for each HTTP flow.")
    
    std::string tmp;
    if (cfg.lookupValue("httpHeadersToPrint", tmp))
    {
        std::transform(tmp.begin(), tmp.end(), tmp.begin(), static_cast <int(*)(int)> (std::tolower));
        httpHeadersToProcess = httpHeadersToProcessBase;
        httpHeadersToPrint.clear();
        
        std::stringstream stream(tmp);
        std::string header;
        while (stream >> header)
        {
            httpHeadersToPrint.insert(header);
            httpHeadersToProcess.insert(header);
        }
        
        if (tmp.length())
            CAPTOOL_MODULE_LOG_CONFIG("printing HTTP headers: " << tmp << ".")
        else
            CAPTOOL_MODULE_LOG_CONFIG("not printing any HTTP headers.")
    }
    
    if (cfg.lookupValue("maxBodySize", maxParsedBodySize))
        CAPTOOL_MODULE_LOG_CONFIG("parsing " << maxParsedBodySize << " bytes from HTTP bodies.")
}

void
HTTP::registerSignature(unsigned blockId, const Signature * signature)
{
    string signatureType = signature->getXmlDefinition()->get_name();
    
    // Get IDs for the general HTTP meta signature
    if (signatureType == "http" && ClassificationMetadata::getInstance().getBlockIdMapper().getId("HTTP") == blockId)
    {
        _httpBlockId = blockId;
        _httpSigId = signature->getId();
        CAPTOOL_MODULE_LOG_INFO("HTTP block ID: " << _httpBlockId << ", sigId: " << _httpSigId)
    }
    // Process real HTTP signatures
    else if (signatureType == "http-header" || signatureType == RESPONSE_BODY_NAME || signatureType == REQUEST_BODY_NAME )
    {
        // Read http signatures
        string name = signature->getXmlDefinition()->get_attribute_value("name");
        string regexp = signature->getXmlDefinition()->get_attribute_value("regexp");
 
        if (signatureType == RESPONSE_BODY_NAME || signatureType == REQUEST_BODY_NAME)
        {
            name = signatureType;
        }
        
        CAPTOOL_MODULE_LOG_INFO("Block: " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId) << ", sigId: " << signature->getId() << ", name: " << name << ", regexp: " << regexp)
    
        // Compile regexp
        const char *error;
        int erroroffset;
    
        pcre * compiledRegexp = pcre_compile(regexp.c_str(), 0, &error, &erroroffset, NULL);
        if (compiledRegexp == NULL)
        {
            CAPTOOL_MODULE_LOG_WARNING("Could not compile regexp: " << regexp)
            CAPTOOL_MODULE_LOG_WARNING("Error at character " << erroroffset << ": " << error)
            CAPTOOL_MODULE_LOG_WARNING("See signature " << signature->getId() << " of block " << blockId)
            exit(-1);
        }
    
        // Read capture flag
        string capture = signature->getXmlDefinition()->get_attribute_value("capture");
    
        // Register hint + regexp in the signature map
        HTTPSignature sig;
        sig.hint = std::make_pair(blockId, signature->getId());
        sig.regexp = compiledRegexp;
        sig.capture = capture == "true";
        // Read pettern name to be used for registering matched pattern
        sig.patternName = signature->getXmlDefinition()->get_attribute_value("pattern-name");
        // If capture is set to true, than pattern name should be specified
        if (sig.capture && sig.patternName == "")
        {
            CAPTOOL_MODULE_LOG_SEVERE("Capture pattern-name parameter not specified for signature " << signature->getId() << " within block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId))
            exit(-1);
        }
        signatureMap.insert(std::make_pair(name, sig));
        
        // Also register HTTP header to the list of http headers to be processed
        if (signatureType == "http-header" && name != "url")
        {
            httpHeadersToProcessBase.insert(name);
        }
    }
}

Module*
HTTP::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")

    Flow * flow = captoolPacket->getFlow().get();
    if (!flow)
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }
    
    bool isHttp = parseHttpMessage(captoolPacket, flow);
    if (!isHttp)
    {
        // Check whether the flow had already been classified as a HTTP flow
        Hintable::HintContainer hints = flow->getHints();
        Hintable::HintContainer::const_iterator it = hints.find(std::make_pair(_httpBlockId, _httpSigId));
        isHttp = it != hints.end();
    }
    
    return isHttp ? _outHttp : _outNonHttp;
}

inline bool
HTTP::seemsHttpRequest(const char * payload, u_int payloadLength)
{
    if (payloadLength < MIN_HTTP_REQUEST_LENGTH)
    {
        // Packet too short to be a valid HTTP request message
        return false;
    }

    string * packetStart = new string(payload, MIN_HTTP_REQUEST_LENGTH);
    
    size_t pos = packetStart->find(' ');
    if (pos == string::npos)
    {
        delete(packetStart);
        return false;
    }
    
    string methodName = packetStart->substr(0, pos);
    delete(packetStart);

    return  methodName.compare("GET") == 0 ||
            methodName.compare("POST") == 0 ||
            methodName.compare("HEAD") == 0 ||
            methodName.compare("OPTIONS") == 0 ||
            methodName.compare("PUT") == 0 ||
            methodName.compare("DELETE") == 0 ||
            methodName.compare("TRACE") == 0 ||
            methodName.compare("CONNECT") == 0;
}

inline bool
HTTP::seemsHttpResponse(const char * payload, u_int payloadLength)
{
    if (payloadLength < MIN_HTTP_RESPONSE_LENGTH)
    {
        // Packet too short to be a valid HTTP response message
        return false;
    }
    
    return payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P' && payload[4] == '/';
}

bool
HTTP::parseHttpMessage(CaptoolPacket *captoolPacket, Flow * flow)
{
    // get payload
    size_t payloadLength = 0;
    const char * payload = (char *)captoolPacket->getPayload(&payloadLength);

    bool isHttpResponse = false;
    bool isHttpRequest = false;

    if (seemsHttpResponse(payload, payloadLength))
    {
        isHttpResponse = true;
    }
    else if (seemsHttpRequest(payload, payloadLength))
    {
        isHttpRequest = true;
    }
    else
    {
        return false;
    }
    
    // Create a string representation of the packet for further processing
    string * requestString = new string(payload, payloadLength);

    try 
    {
        if (isHttpRequest)
        {
            // Parse request line 
            // ...should not return string::npos if we already get so far
            size_t urlStart =  requestString->find(' ') + 1;
            size_t urlEnd = requestString->find(" HTTP/", urlStart);
    
            if (urlEnd == string::npos)
            {
                CAPTOOL_MODULE_LOG_FINE("Seemed HTTP request line but it is incomplete (no HTTP version) (no. " << captoolPacket->getPacketNumber() << ")");
                throw std::runtime_error("");
            }

            processHttpHeaderField("url", requestString->substr(urlStart, urlEnd - urlStart), flow);

            if (_printHttpMethod)
            {
                registerOption(flow, HTTP_METHOD_OPTION_NAME, requestString->substr(0, urlStart - 1));
            }
        
            if (_printUrl)
            {
                registerOption(flow, URL_OPTION_NAME, requestString->substr(urlStart, urlEnd - urlStart));
            }
        }
        else if (isHttpResponse)
        {
            // Parse status line of response
            size_t versionEnd =  requestString->find(' ');
    
            if (versionEnd == string::npos)
            {
                CAPTOOL_MODULE_LOG_FINE("Seemed HTTP response line but it is incomplete (no space after HTTP version) (no. " << captoolPacket->getPacketNumber() << ")")
                throw std::runtime_error("");
            }

            string statusCode = requestString->substr(versionEnd + 1, 3);
            if (statusCode[0] < '0' || statusCode[0] > '9' || statusCode[1] < '0' || statusCode[1] > '9' || statusCode[2] < '0' || statusCode[2] > '9' || (*requestString)[versionEnd + 4] != ' ')
            {
                CAPTOOL_MODULE_LOG_FINE("Seemed HTTP response line but it is incomplete (invalid or missing status code: " << statusCode << (*requestString)[versionEnd + 4] << ") (no. " << captoolPacket->getPacketNumber() << ")")
                throw std::runtime_error("");
            }

            if (_printStatusCode)
            {
                registerOption(flow, STATUS_CODE_OPTION_NAME, statusCode);
            }
        }
    
        // Register a general HTTP hint
        flow->setHint(_httpBlockId, _httpSigId);
    
        // Parse HTTP headers
        if (httpHeadersToProcess.empty())
        {
            throw std::runtime_error("");
        }
    
        size_t headersStart = requestString->find("\r\n");
        if (headersStart == string::npos)
        {
            CAPTOOL_MODULE_LOG_FINE("Could not find the terminating CRLF sequence at the end of the first line of the HTTP message (no. " << captoolPacket->getPacketNumber() << ")")
            throw std::runtime_error("");
        }
        else
        {
            headersStart += 2;
        }

        size_t headersEnd = requestString->find("\r\n\r\n", headersStart);
    
        bool parseBody = true;
        if (headersEnd == string::npos) 
        {
            headersEnd = requestString->rfind("\r\n");
            // Incomplete header, body probably starts only in the next packet
            parseBody = false;
        }
    
        for (size_t currentHeaderEnd, currentHeaderStart = headersStart; currentHeaderStart < headersEnd; currentHeaderStart = currentHeaderEnd + 2)
        {
            // Should not result in string::npos
            currentHeaderEnd = requestString->find("\r\n", currentHeaderStart);
        
            size_t fieldNameEnd = requestString->find(':', currentHeaderStart);
            if (fieldNameEnd > currentHeaderEnd || fieldNameEnd == string::npos)
            {
                // Should not happen
                CAPTOOL_MODULE_LOG_WARNING("Malformed HTTP request header. No \":\" separator within header line (no. " << captoolPacket->getPacketNumber() << ")");
                break; 
            }
        
            string headerName = requestString->substr(currentHeaderStart, fieldNameEnd - currentHeaderStart);
            // Transform to lower-case (HTTP header names are case insensitive)
            std::transform(headerName.begin(), headerName.end(), headerName.begin(), static_cast <int(*)(int)> (tolower));
            if (httpHeadersToProcess.find(headerName) == httpHeadersToProcess.end())
            {
                // This header is not to be processed
                continue;
            }
           
            size_t fieldValueStart = fieldNameEnd + 1;
            while (requestString->at(fieldValueStart) == ' ' || requestString->at(fieldValueStart) == '\t')
            {
                ++fieldValueStart;
            }
            string headerValue = requestString->substr(fieldValueStart, currentHeaderEnd - fieldValueStart);
        
            processHttpHeaderField(headerName, headerValue, flow);
        }

        if (parseBody)
        {
            processHttpBody(requestString, headersEnd+4, flow, isHttpResponse);
        }
    }
    catch (const std::exception& e)
    {   
        delete(requestString);
        return false;
    }
    
    delete(requestString);
    return true;
}

void 
HTTP::processHttpBody(const string * payload, size_t offset, Flow * flow, bool isResponse)
{
    size_t bodyLength = payload->length() - offset > maxParsedBodySize ? maxParsedBodySize : payload->length() - offset;
    string body = payload->substr(offset, bodyLength);
    
    std::pair<HTTPSignatureMap::const_iterator,HTTPSignatureMap::const_iterator> range = signatureMap.equal_range(isResponse ? RESPONSE_BODY_NAME : REQUEST_BODY_NAME);
    for (HTTPSignatureMap::const_iterator it = range.first; it != range.second; ++it)
    {
        Hintable::Hint hint = it->second.hint;
        pcre * regexp = it->second.regexp;

        int ovector[10];
        int rc;
    
        rc = pcre_exec(regexp, NULL, body.c_str(), bodyLength, 0, 0, ovector, 10);
        if (rc > 0)
        {
            flow->setHint(hint.first, hint.second);
        }
    }
}

void 
HTTP::processHttpHeaderField(string headerName, string headerValue, Flow * flow)
{
    // Test all regexps registered for this header name
    std::pair<HTTPSignatureMap::const_iterator,HTTPSignatureMap::const_iterator> range = signatureMap.equal_range(headerName);
    for (HTTPSignatureMap::const_iterator it = range.first; it != range.second; ++it)
    {
        Hintable::Hint hint = it->second.hint;
        pcre * regexp = it->second.regexp;

        int ovector[10];
        int rc;
    
        rc = pcre_exec(regexp, NULL, headerValue.c_str(), headerValue.length(), 0, 0, ovector, 10);
        if (rc > 0)
        {
//            CAPTOOL_MODULE_LOG_WARNING("Header: " << headerName << ", value: " << headerValue << " matches hint " << hint.first << "," << hint.second)
            flow->setHint(hint.first, hint.second);
        }
        if (rc > 1 && it->second.capture)
        {
            // Subpattern start is at the beginning of first capture block
            int patternStart = ovector[2];
            // Subpattern end is at the end of the entire matched pattern if no other capture blocks were defined and at the beginning of the second capture block if such a block had been defined
            int patternEnd = rc == 2 ? ovector[1] : ovector[3];
            registerOption(flow, it->second.patternName, headerValue.substr(patternStart, patternEnd-patternStart));
        }
    }
    
    // Register header as a flow option to be printed out in the flow log
    if (httpHeadersToPrint.find(headerName) != httpHeadersToPrint.end())
    {
        registerOption(flow, headerName, headerValue);
    }
}

void
HTTP::registerOption(Flow * flow, const string& optionName, const string& optionValue)
{
    if (_anonymize)
    {
        size_t pos = optionValue.find_first_of('?');
        if (pos != string::npos)
        {
            // Remove parameters after the ? in the URL which might contain sensitive information
            flow->registerOption(optionName, optionValue.substr(0, pos+1), true);
            return;
        }
        pos = optionValue.find("%3F"); // URL encoding for the "?" character
        if (pos != string::npos)
        {
            // Remove parameters after the ? in the URL which might contain sensitive information
            flow->registerOption(optionName, optionValue.substr(0, pos+3), true);
            return;
        }
    }

    // HTTP field can be registered unchanged
    flow->registerOption(optionName, optionValue, true);
}

void
HTTP::describe(const captool::CaptoolPacket *, std::ostream *)
{
}
