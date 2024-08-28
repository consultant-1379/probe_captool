/*
 * ClassificationMetadata.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "ClassificationMetadata.h"
#include "util/log.h"
#include "util/crypt.h"
#include <string>
#include <fstream>
#include <sstream>

const unsigned ClassificationMetadata::MIN_CLASSIFIER_SIG_ID = 1000;
ClassificationMetadata * ClassificationMetadata::instance = 0;

ClassificationMetadata::ClassificationMetadata ()
  : parser(),
    _initialized(false),
    _blockIdMapper(),
    _facetIdMapper(),
    _focusIdMapper(),
    _numberOfSignatures(0),
    _previousClassifierSigId(0),
    _previousBlockSigId(0),
    _classifierMap(),
    _finalMask(),
    _blocks()
{}

ClassificationMetadata::~ClassificationMetadata ()
{
    for (vector<ClassificationBlock*>::const_iterator i = _blocks.begin(); i != _blocks.end(); ++i)
        delete *i;
}

ClassificationMetadata &
ClassificationMetadata::getInstance () {
    if (! instance)
        instance = new ClassificationMetadata ();
    return *instance;
}

void
ClassificationMetadata::destroyInstance () {
    delete instance;
    instance = 0;
}

void
ClassificationMetadata::initialize(libconfig::Config* config)
{
    // Initialization should happen only once
    if (_initialized)
    {
        return;
    }

    assert(config != 0);
    
    string signatureConfigFile;
    if (!config->lookupValue("captool.classification.fileName", signatureConfigFile))
    {
        CAPTOOL_LOG_WARNING("captool.classification.fileName not set, unable to perform traffic classification")
        return;
    }

    CAPTOOL_LOG_CONFIG("loading classification config from " << signatureConfigFile);

    try
    {
        // Parse and validate XML classification config
        parser.set_validate(true);
        bool encrypted = false;
        if (config->lookupValue("captool.securityManager.encryptedClassification", encrypted) && encrypted) {
            CAPTOOL_LOG_FINE("classification rules encrypted;  will check password")
            std::ifstream file(signatureConfigFile.c_str());
            std::stringstream ss;
            decrypt(file, ss);
            // HACK:  File name is not known during parsing from string, therefore supply DTD file path
            // and validate by hand.  All this because we prefer relative paths in the XML.
            parser.set_validate(false);
            parser.parse_stream(ss);
            xmlpp::Dtd * dtd = parser.get_document()->get_internal_subset();
            Glib::ustring dtdfilename = dtd->get_system_id();
            std::size_t pos = signatureConfigFile.find_last_of('/');
            std::string path = (pos == std::string::npos ? "" : signatureConfigFile.substr(0, pos + 1)).append(dtdfilename);
            xmlpp::DtdValidator val(path);
            val.validate(parser.get_document());
        } else {
            CAPTOOL_LOG_FINE("classification rules unencrypted;  will read from file")
            parser.parse_file(signatureConfigFile);
        }
        
        const xmlpp::Element* root = parser.get_document()->get_root_node();

        // Process block independent global options, e.g. classifiers, facets
        const Node::NodeList globals = root->get_children("global");
        for (Node::NodeList::const_iterator itGlobals = globals.begin(); itGlobals != globals.end(); ++itGlobals)
        {
            const Element* global = dynamic_cast<const Element*>(*itGlobals);
            readGlobalElement(global);

            // Only one global element is allowed
            break;
        }

        // Process signature specifications for all blocks
        const Node::NodeList blocks = root->get_children("block");
        for (Node::NodeList::const_iterator itBlock = blocks.begin(); itBlock != blocks.end(); ++itBlock)
        {
            const Element* block = dynamic_cast<const Element*>(*itBlock);
            readBlockElement(block);
        }
    }
    catch (const std::exception& e)
    {
        CAPTOOL_LOG_SEVERE("XML load exception: " << e.what());
        exit(-1);
    }

    _initialized = true;
}

void
ClassificationMetadata::readGlobalElement(const Element * global)
{
    // Process classifiers
    _previousClassifierSigId = 0;
    const Node::NodeList classifiers = global->get_children("classifier");
    for (Node::NodeList::const_iterator itClassifier = classifiers.begin(); itClassifier != classifiers.end(); ++itClassifier)
    {
        const Element* classifier = dynamic_cast<const Element*>(*itClassifier);

        // Read classifier atributes
        string classifierName = classifier->get_attribute_value("name");
        unsigned sigId;
        getattrval(classifier, "sigId") >> sigId;
        
        // Verify sigId numbering
        if (sigId < MIN_CLASSIFIER_SIG_ID)
        {
            throw std::runtime_error("sigId attribute of classifier " + classifierName + " is out of range");
        }

        if (sigId <= _previousClassifierSigId)
        {
            throw std::runtime_error("Invalid sigId numbering at classifier " + classifierName + ": classifier sigIds have to be unique and incrementally numbered");
        }
        _previousClassifierSigId = sigId;

        bool isFinal = classifier->get_attribute_value("final") == "true";
        // Final implies standalone (even if it is not explicitely specified in the XML)
        bool isStandalone = classifier->get_attribute_value("standalone") == "true" || isFinal;

        _classifierMap.insert(std::make_pair(classifierName, ClassifierDescriptor(sigId, isStandalone, isFinal)));
    }
     
    // Process facet list
    const Node::NodeList facets = global->get_children("facet");
    for (Node::NodeList::const_iterator itFacet = facets.begin(); itFacet != facets.end(); ++itFacet)
    {
        const Element* facet = dynamic_cast<const Element*>(*itFacet);

        // Read facet atributes
        bool required = facet->get_attribute_value("required") == "true";
        string facetName = facet->get_attribute_value("name");
        
        unsigned facetId = _facetIdMapper.registerName(facetName);
        if (facetId >= _finalMask.size())
        {
            _finalMask.resize(facetId+1);
        }
        _finalMask.set(facetId, required);
    }
}

TagContainer
ClassificationMetadata::readTags(const Element * container)
{
    TagContainer tagContainer(_facetIdMapper.size());
    const Node::NodeList tags = container->get_children("tag");
    for (Node::NodeList::const_iterator itTag = tags.begin(); itTag != tags.end(); ++itTag)
    {
        const Element* tag = dynamic_cast<const Element*>(*itTag);

        string tagName = tag->get_attribute_value("name");
        string tagValue = tag->get_attribute_value("value");
        
        unsigned tagId = _facetIdMapper.getId(tagName);
        if (tagId == (unsigned)-1)
        {
            throw std::runtime_error("Undefined facet: " + tagName);
        }
        
        tagContainer.setTag(tagId, _focusIdMapper.registerName(tagValue));
    }
    return tagContainer;
}

void
ClassificationMetadata::readBlockElement(const Element * block)
{
    string blockName = block->get_attribute_value("name");
    unsigned blockId = _blockIdMapper.registerName(blockName);

    // Read classification tags assigned to this block
    const TagContainer & tags = readTags(block);

    // Process preconditions for this block
    const Element * precondition = 0;
    const Node::NodeList preconditions = block->get_children("precondition");
    for (Node::NodeList::const_iterator itPrec = preconditions.begin(); itPrec != preconditions.end(); ++itPrec)
    {
        precondition = dynamic_cast<const Element*>(*itPrec);

        // Stop after reading the first element (only one precondition element allowed per block)
        break;
    }
    
    // Create and register block descriptior
    ClassificationBlock * classificationBlock = new ClassificationBlock(tags, precondition);
    _blocks.resize(blockId+1);
    _blocks[blockId] = classificationBlock;

    // Process signatures for this block
    _previousBlockSigId = 0;
    const Node::NodeList signatureContainers = block->get_children("signature");
    for (Node::NodeList::const_iterator itSig = signatureContainers.begin(); itSig != signatureContainers.end(); ++itSig)
    {
        const Element* signatureContainer = dynamic_cast<const Element*>(*itSig);
        Signature * signature = readSignatureElement(blockId, blockName, signatureContainer);
        classificationBlock->addSignature(signature);
    }
    
    // Process rules for this block
    const Node::NodeList rules = block->get_children("rule");
    for (Node::NodeList::const_iterator itRule = rules.begin(); itRule != rules.end(); ++itRule)
    {
        const Element* rule = dynamic_cast<const Element*>(*itRule);
        classificationBlock->addRule(rule);
    }
}

Signature *
ClassificationMetadata::readSignatureElement(unsigned, string blockName, const Element * signatureContainer)
{
    unsigned sigId;
    getattrval(signatureContainer, "id") >> sigId;

    // Verify sigId numbering within block
    if (sigId >= MIN_CLASSIFIER_SIG_ID)
    {
        throw std::runtime_error("Signature ID out of range. See block " + blockName);
    }
    if (sigId <= _previousBlockSigId)
    {
        throw std::runtime_error("Invalid signature ID numbering at block " + blockName + ": signature IDs within a block have to be unique and incrementally numbered");
    }
    _previousBlockSigId = sigId;

    bool isFinal = signatureContainer->get_attribute_value("final") == "true";
    // Final implies standalone (even if it is not explicitely specified in the XML)
    bool isStandalone = signatureContainer->get_attribute_value("standalone") == "true" || isFinal;

    // Read signature specific classification tags
    const TagContainer & tags = readTags(signatureContainer);
    // Signature specific tags can only be defined for standalone signatures
    if (!tags.isEmpty() && !isStandalone)
    {
        CAPTOOL_LOG_SEVERE("Signature-specific tags can only be defined for standalone signatures. However, signature " << sigId << " of " << blockName << " is not standalone.")
        exit(-1);
    }

    const Node::NodeList signatureContent = signatureContainer->get_children();
    // Find first element child node and skip other stuff (e.g. comments)
    for (Node::NodeList::const_iterator itSigContent = signatureContent.begin(); itSigContent != signatureContent.end(); ++itSigContent)
    {
        const Element* sig = dynamic_cast<const Element*>(*(itSigContent));
        if (!sig) 
        {
            // Node within signature container is not an element (e.g. a comment)
            continue;
        }

        // skip tags
        if (sig->get_name() == "tag")
        {
            continue;
        }

        ++_numberOfSignatures;
        Signature * signature = new Signature(sigId, isStandalone, isFinal, sig, tags);
        
        // Stop after reading the first element (only one signature element allowed per signature container)
        return signature;
    }
    
    // Cannot get here with a validated XML config
    throw std::runtime_error("No signature element in block " + blockName);
}
