/*
 * ClassAssigner.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CLASS_ASSIGNER_H__
#define __CLASS_ASSIGNER_H__

#include <string>

#include "libconfig.h++"

#include <map>
#include <boost/dynamic_bitset.hpp>

#include "modulemanager/Module.h"
#include "captoolpacket/CaptoolPacket.h"

#include <classification/FacetClassified.h>
#include <classification/ClassificationMetadata.h>
#include "classification/Classifier.h"

#include "ClassificationConstraints.h"

using boost::dynamic_bitset;
using std::map;
using std::set;
using std::multimap;

using captool::CaptoolPacket;

/**
 * Module assigning final application class based on classification hints provided by other classifier modules.
 * TBD: update this description
 * The decision process works as follows:
 * Input data: hints and hinted_application for this flow (as bitsets)
 * For each hintted application
 *      - Check general exclude preconditions
 *      - Check for standalone "final" or "reliable" application hints
 *      - Evaluate rules of this application
 */
class ClassAssigner : public captool::Module, public Classifier
{
    public:
        
        /**
         * Constructor.
         *
         * @param name the unique name of the module
         */    
        explicit ClassAssigner(std::string name);
        
        /**
         * Destructor.
         */    
        ~ClassAssigner();
        
        // inherited from Module
        Module* process(captool::CaptoolPacket* captoolPacket);
        
    protected:
        
        // inherited from Module
        void initialize(libconfig::Config* config);

    private:
        
        void registerBlock(unsigned blockId, const ClassificationBlock * block);

        void postprocessBlock(unsigned blockId, const ClassificationBlock * block);

        void registerSignature(unsigned blockId, unsigned sigId, bool isStandalone, bool isFinal, const TagContainer& tags);
        
        void registerPrecondition(unsigned blockId, const Element * precondition);
        
        void registerRule(unsigned blockId, const Element * rule);
        
        void updateFacetBitmask(const dynamic_bitset<>* maks, const TagContainer& tags);

        void updateFacetBitmasks();

        /**
         * Create exclude mask of hints based on XML config. Can be used both for precondition and rule element parsing.
         * 
         * @param blockId the ID of the block whose precondition or rule element is parsed
         * @param container the pointer to the XML element containing exclude tags
         *
         * @return a pointer to the generated exclude hint mask
         */
        dynamic_bitset<> * createExcludeMask(unsigned blockId, const Element * container);

        /**
         * Create allow mask of hints based on XML config. Can be used both for precondition and rule element parsing.
         * 
         * @param blockId the ID of the block whose precondition or rule element is parsed
         * @param container the pointer to the XML element containing allow tags
         *
         * @return a pointer to the generated allow hint mask
         */
        dynamic_bitset<> * createAllowMask(unsigned blockId, const Element * container);

        /**
         * Create include mask of hints based on XML config. Can be used to parse rule elements.
         * 
         * @param blockId the ID of the block whose rule element is parsed
         * @param container the pointer to the XML element containing include tags
         *
         * @return a pointer to the generated include hint mask
         */
        dynamic_bitset<> * createIncludeMask(unsigned blockId, const Element * container);

        /**
         * Process all constraint tags of the given XML container
         *
         * @return a set containing the ID of all constraint elements
         */
        set<ClassificationConstraints::Constraint> * processConstraints(unsigned blockId, const Element * container);

        /**
         * Returns true if the given packet and the associated flow satisfies all the specified constraints.
         */
        bool evaluateConstraints(const set<ClassificationConstraints::Constraint> * contraints, CaptoolPacket * packet);

        /**
         * Set tags for the given flow.
         *
         * @param tags the set of tags to be set for the given flow
         * @return a bitmask where the ith flag is set if a tag for the ith facet have been set
         */
        dynamic_bitset<> setTags(Flow * flow, unsigned blockId, bool isFinal, const TagContainer& tags);
        
        /** Describes a classification rule. TBD: implement it as a class */
        typedef struct {
            //  None of these can appear among flow hints
            dynamic_bitset<> * excludedHints;
            // All of these should appear among flow hints
            dynamic_bitset<> * includedHints;
            // If true, than flow class can be tagged final
            bool isFinal;
            // Additional classification tags specific to this rule
            TagContainer tags;
            // Constraints
            set<ClassificationConstraints::Constraint> * constraints;
        } Rule;

        /** Describes preconditions for a given classification block. TBD: implement it as a class */
        typedef struct {
            // If the flow has any of the hints marked by this bitmask, than the flow cannot be set to this block.
            dynamic_bitset<> * excludedHints;
            // Constraints
            set<ClassificationConstraints::Constraint> * constraints;
        } Precondition;

        /** 
         * Total number of hints, also including block independent hints for each block 
         * (which are not explicitely present in block signature definition, e.g. server port search hints) 
         */
        int _numberOfHints;

        /** Position of next hint when registering signatures from config */
        unsigned _nextHintPosition;

        /** Maps hints to their position in hint bitmasks. This position is assigned incrementally while reading the classification.xml config. */
        map<Hintable::Hint, unsigned> _hintPositionMap;

        /** Bitmask for standalone hints (which can be used for classification in themselves) */
        dynamic_bitset<> * _standaloneHints;

        /** Bitmask for final hints (which are so reliable that flow class can be tagged final) */
        dynamic_bitset<> * _finalHints;

        /** Bitmask for hints having extra (hint specific) tags specified */
        dynamic_bitset<> * _taggedHints;

        /** Maps hint position to associated tags */
        map<unsigned, TagContainer> _hintTagMap;
        
        /** Maps bitmask used to select hints for a given block to block ID */
        map<unsigned, dynamic_bitset<> *> _blockHintMaskMap;

        /** Maps blocks to their associated rules */
        multimap<unsigned, Rule*> _ruleMap;

        /** Maps preconditions descriptors to block IDs. */
        map<unsigned, Precondition *> _preconditionMap;
        
        /** Facet ID -> bitmask for hints which set a tag for the given facet */
        map<unsigned, dynamic_bitset<> *> _facetHintMaskMap;
};

#endif // __CLASS_ASSIGNER_H__
