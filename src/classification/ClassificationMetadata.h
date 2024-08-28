/*
 * ClassificationMetadata.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CLASSIFICATION_METADATA_H__
#define __CLASSIFICATION_METADATA_H__

#include <string>
#include <map>
#include <boost/dynamic_bitset.hpp>

#include <libxml++/libxml++.h>
#include "libconfig.h++"
#include <stdexcept>

#include "IdNameMapper.h"
#include "ClassifierDescriptor.h"
#include "ClassificationBlock.h"

// Retreive an attribute of a DOM element (TBD: use static inline function instead)
#define getattrval(elem, attrname) \
            if (elem->get_attribute_value(attrname) == "") \
                throw std::runtime_error(string(elem->get_name()).append(" no such attribute: ").append(attrname)); \
            std::istringstream(elem->get_attribute_value(attrname))

using std::string;
using std::map;
using std::multimap;
using std::vector;
using xmlpp::Element;
using xmlpp::Node;
using xmlpp::Document;

namespace captool {
    class Captool;
}

/**
 * Provides classification metadata read from classification xml config file. 
 * Also performs generic (non module specific) sanity check of the xml config.
 *
 * @par Configuration
 * The following settings should be put under section named @c classification below the
 * root node:
 * @code
 *   classification: {
 *     fileName = "conf/classification.xml";               // path to xml file describing traffic classification signatures and rules
 *   };
 * @endcode
 *
 * Also, the following security setting is honored:
 * @code
 *   securityManager: {
 *     ...
 *     encryptedClassification = true;    // ask for decryption password on startup
 *   };
 * @endcode
 */
class ClassificationMetadata
{
    public:
        
        /** Return instance variable for this class */
        static const ClassificationMetadata & getInnstance ();
        
        /** Return singleton instance of this class. */
        static ClassificationMetadata & getInstance ();
        
        /** Returns true if metada had been successfully initilized from xml config, returns false otherwise */
        bool isInitialized();
    
        /** Read classification metadata from xml config file */
        void initialize(libconfig::Config* config);

        const IdNameMapper& getBlockIdMapper();
        
        const IdNameMapper& getFacetIdMapper();
        
        const IdNameMapper& getFocusIdMapper();
        
        /** Returns the total number of signatures read from classification.xml */
        int getNumberOfSignatures();

        /** Returns a classifier name -> classifier descriptor map */
        const map<string,ClassifierDescriptor>& getClassifierDescriptors();
        
        /** 
         * Get the sigId assigned to the given classifier 
         *
         * @param classifierName the name of the classifier whose sigId is queried
         * @return the sigId assigned to the classifer in the xml config or -1 if no such classifier is defined
         */
        unsigned getClassifierId(string classifierName);
        
        /** 
         * Get bitmask defining which facets need to be defined in order to mark a flow as final 
         * (from a classification point of view). 
         *
         * @return a bitmask where the ith bit marks whether a tag for the ith facet is required in order to set a flow final or not
         */
        const dynamic_bitset<>& getFinalMask();
        
        /**
         * Get block descriptor of a specific block in the xml classification config
         *
         * @param blockId the ID of the queried block
         * @return pointer to the block descriptor object for the given block Id
         */
        const ClassificationBlock* getBlock(unsigned blockId);
        
        /** 
         * Read classification tags from an XML container 
         *
         * @param container the XML elements whose tags are to be read
         * @return container of tags (empty if there were no tags)
         */
        TagContainer readTags(const Element * container);
        
        void destroyInstance ();
        
    private:
        
        ClassificationMetadata ();
        
        ~ClassificationMetadata ();
        
        static ClassificationMetadata * instance;
        
        /**
         * The parsed classification XML.
         * We need to keep it around during the whole initialization process
         * because _blocks stores pointers to document elements.
         */
        xmlpp::DomParser parser;

        void readGlobalElement(const Element * globalElement);
        
        void readBlockElement(const Element * blockElement);

        /** Read a signature element from the XML config */
        Signature * readSignatureElement(unsigned blockId, string blockName, const Element * signatureElement);
        
        /** True if the whole classification.xml has already been read once and false otherwise. */
        bool _initialized;
        
        /** block ID <-> block name mapper */
        IdNameMapper _blockIdMapper;

        /** facet ID <-> facet name mapper */
        IdNameMapper _facetIdMapper;

        /** focus ID <-> focus name mapper */
        IdNameMapper _focusIdMapper;

        /** Number of signatures read from the xml config */
        unsigned _numberOfSignatures;

        /** The lowest ID of the classifier sig ID range (signature IDs within blocks have to be smaller than this) */
        static const unsigned MIN_CLASSIFIER_SIG_ID;
        
        /** Sig ID of the previously read classifier element */
        unsigned _previousClassifierSigId;
        
        /** Sig ID of the previously read signature within the current block */
        unsigned _previousBlockSigId;
        
        /** Maps classifier data to classifier nanme */
        map<string,ClassifierDescriptor> _classifierMap;
        
        /** The ith bit marks whether a tag for the ith facet is required in order to set a flow final or not */
        dynamic_bitset<> _finalMask;
        
        /** The ith element of this vector contains the classification information of the ith block */
        vector<ClassificationBlock*> _blocks;
};

inline bool
ClassificationMetadata::isInitialized()
{
    return _initialized;
}

inline int
ClassificationMetadata::getNumberOfSignatures()
{
    return _numberOfSignatures;
}

inline const IdNameMapper&
ClassificationMetadata::getBlockIdMapper()
{
    return _blockIdMapper;
}

inline const IdNameMapper&
ClassificationMetadata::getFacetIdMapper()
{
    return _facetIdMapper;
}

inline const IdNameMapper&
ClassificationMetadata::getFocusIdMapper()
{
    return _focusIdMapper;
}

inline const map<string,ClassifierDescriptor>&
ClassificationMetadata::getClassifierDescriptors()
{
    return _classifierMap;
}

inline unsigned
ClassificationMetadata::getClassifierId(string classifierName)
{
    map<string,ClassifierDescriptor>::const_iterator it = _classifierMap.find(classifierName);
    return it == _classifierMap.end() ? (unsigned)-1 : it->second.getId();
}

inline const dynamic_bitset<>&
ClassificationMetadata::getFinalMask()
{
    return _finalMask;
}

inline const ClassificationBlock*
ClassificationMetadata::getBlock(unsigned blockId)
{
    return _blocks[blockId];
}

#endif //__CLASSIFICATION_METADATA_H__