/*
 * ClassAssigner.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>
#include <stdlib.h>
#include <iostream>

#include "modulemanager/ModuleManager.h"

#include "ClassAssigner.h"
#include "flow/Flow.h"

using std::string;

using captool::CaptoolPacket;
using captool::Module;
using captool::ModuleManager;

DEFINE_CAPTOOL_MODULE(ClassAssigner)

ClassAssigner::ClassAssigner(string name)
    : Module(name),
      _nextHintPosition(0)
{
}

ClassAssigner::~ClassAssigner()
{
    // Delete hint and facet bitmasks
    delete(_standaloneHints);
    delete(_finalHints);
    delete _taggedHints;
    for (multimap<unsigned, dynamic_bitset<>*>::const_iterator i = _blockHintMaskMap.begin(); i != _blockHintMaskMap.end(); ++i)
        delete i->second;
    for (multimap<unsigned, Rule*>::const_iterator i = _ruleMap.begin(); i != _ruleMap.end(); ++i)
    {
        Rule * r = i->second;
        delete r->includedHints;
        delete r->excludedHints;
        delete r->constraints;
        delete r;
    }
    for (multimap<unsigned, Precondition*>::const_iterator i = _preconditionMap.begin(); i != _preconditionMap.end(); ++i)
    {
        Precondition * p = i->second;
        delete p->excludedHints;
        delete p->constraints;
        delete p;
    }
    for (map<unsigned,dynamic_bitset<>*>::iterator it = _facetHintMaskMap.begin(); it != _facetHintMaskMap.end(); ++it)
        delete it->second;
}

void
ClassAssigner::initialize(libconfig::Config* config)
{
    assert(config != 0);

    CAPTOOL_MODULE_LOG_FINE("initializing.")

    Module::initialize(config);
    
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();
    
    if (! cmd.isInitialized())
    {
        CAPTOOL_MODULE_LOG_SEVERE("Classification metadata not initialized, unable to load classification modules")
        exit(-1);
    }

    // Determine hint bitmask size
    _numberOfHints = cmd.getNumberOfSignatures() + cmd.getClassifierDescriptors().size() *
                        cmd.getBlockIdMapper().size();

    // Initialize facet and hint bitmasks
    _standaloneHints = new dynamic_bitset<>(_numberOfHints);
    _finalHints = new dynamic_bitset<>(_numberOfHints);
    _taggedHints = new dynamic_bitset<>(_numberOfHints);
    for (unsigned i=1; i<= cmd.getFacetIdMapper().size(); i++)
    {
        _facetHintMaskMap.insert(std::make_pair(i, new dynamic_bitset<>(_numberOfHints)));
    }

    // Process all classification blocks
    for (unsigned blockId = 1; blockId <= cmd.getBlockIdMapper().size(); blockId++)
    {
        const ClassificationBlock * block = cmd.getBlock(blockId);
        registerBlock(blockId, block);
    }

    // Create facet bitmasks.
    // This has to be completed before processing rules and preconditions,
    // but can only be performed after having processed all signatures
    updateFacetBitmasks();

    // Post-process all classification blocks (rules and preconditions)
    // Run tasks requiring that all signature be already registered
    for (unsigned blockId = 1; blockId <= cmd.getBlockIdMapper().size(); blockId++)
    {
        const ClassificationBlock * block = cmd.getBlock(blockId);
        postprocessBlock(blockId, block);
    }

    // Print facet and hint bitmasks
    for (unsigned i=1; i<= cmd.getFacetIdMapper().size(); i++)
    {
        std::map<unsigned, dynamic_bitset<>*>::const_iterator itFacet = _facetHintMaskMap.find(i);
        // Not found check unnecessary (everything should have been inserted at the beginning of this function)
        CAPTOOL_MODULE_LOG_INFO("Facet hint mask for " << cmd.getFacetIdMapper().getName(i) << ": " << *(itFacet->second))
    }
    CAPTOOL_MODULE_LOG_INFO("Standalone hints: " << *_standaloneHints)
    CAPTOOL_MODULE_LOG_INFO("Final hints:      " << *_finalHints)
    CAPTOOL_MODULE_LOG_INFO("Tagged hints:      " << *_taggedHints)
}

void
ClassAssigner::registerBlock(unsigned blockId, const ClassificationBlock * block)
{
    // Go through each classifier and register its application independent sigId for this block
    map<string,ClassifierDescriptor> classifierMap = ClassificationMetadata::getInstance().getClassifierDescriptors();
    for (map<string,ClassifierDescriptor>::const_iterator itClassifier = classifierMap.begin(); itClassifier != classifierMap.end(); ++itClassifier)
    {
        ClassifierDescriptor classifier = itClassifier->second;
        registerSignature(blockId, classifier.getId(), classifier.isStandalone(), classifier.isFinal(), TagContainer()); // Default empty tag container
    }
    
    // Register all signatures of the block
    pair<ClassificationBlock::SignatureIterator,ClassificationBlock::SignatureIterator> iteratorPair = block->getSignatureIterators();
    for (ClassificationBlock::SignatureIterator itSig = iteratorPair.first; itSig != iteratorPair.second; ++itSig)
    {
        const Signature * signature = itSig->second;
        registerSignature(blockId, signature->getId(), signature->isStandalone(), signature->isFinal(), signature->getTags());
    }
}

void 
ClassAssigner::registerSignature(unsigned blockId, unsigned sigId, bool isStandalone, bool isFinal, const TagContainer& tags)
{
    Hintable::Hint hint = std::make_pair(blockId, sigId);
    
    // Update hint position map
    _hintPositionMap.insert(std::make_pair(hint, _nextHintPosition));
    
    // Update hint bitmasks
    if (isStandalone)
    {
        _standaloneHints->set(_nextHintPosition);
    }
    if (isFinal)
    {
        _finalHints->set(_nextHintPosition);
    }
    if (!tags.isEmpty())
    {
        _taggedHints->set(_nextHintPosition);
        _hintTagMap.insert(std::make_pair(_nextHintPosition, tags));
    }
    
    // Update block hint mask map
    map<unsigned, dynamic_bitset<> *>::const_iterator it = _blockHintMaskMap.find(blockId);
    dynamic_bitset<> * hintMask;
    if (it == _blockHintMaskMap.end())
    {
        hintMask = new dynamic_bitset<>(_numberOfHints);
        _blockHintMaskMap.insert(std::make_pair(blockId, hintMask));
    }
    else
    {
        hintMask = it->second;
    }
    hintMask->set(_nextHintPosition);

    ++_nextHintPosition;
}

void
ClassAssigner::postprocessBlock(unsigned blockId, const ClassificationBlock * block)
{
    // Register precondition
    const Element * precondition = block->getPreconditions();
    if (precondition != NULL)
    {
        registerPrecondition(blockId, precondition);
    }
    
    // Register rules
    for (vector<const Element *>::const_iterator itRule = block->getRules().begin(); itRule != block->getRules().end(); ++itRule)
    {
        registerRule(blockId, *itRule);
    }
}


void
ClassAssigner::updateFacetBitmasks()
{
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();
    
    // Go through all blocks
    for (unsigned blockId = 1; blockId <= cmd.getBlockIdMapper().size(); blockId++)
    {
        const ClassificationBlock * block = cmd.getBlock(blockId);
        
        // Get hint mask for this block
        map<unsigned, dynamic_bitset<>*>::const_iterator itMask = _blockHintMaskMap.find(blockId);
        assert(itMask != _blockHintMaskMap.end());
        // Update facet bitmask based on block tags
        updateFacetBitmask(itMask->second, block->getTags());
        
        // Update facet bitmasks for rules
        const vector<const Element *> rules = block->getRules();
        for (vector<const Element *>::const_iterator itRule = rules.begin(); itRule != rules.end(); ++itRule)
        {
            dynamic_bitset<>* mask = createIncludeMask(blockId, *itRule);
            const TagContainer & tags = cmd.readTags(*itRule);
            updateFacetBitmask(mask, tags);
            delete mask;
        }
    }
    
    // Go through signature tags
    for (map<unsigned,TagContainer>::const_iterator itSig = _hintTagMap.begin(); itSig != _hintTagMap.end(); ++itSig)
    {
        dynamic_bitset<>* mask = new dynamic_bitset<>(_numberOfHints);
        mask->set(itSig->first);
        updateFacetBitmask(mask, itSig->second);
        delete mask;
    }
}

void
ClassAssigner::updateFacetBitmask(const dynamic_bitset<> * mask, const TagContainer& tags)
{
    // Aply mask for each affected facet
    for (unsigned i=1; i<= ClassificationMetadata::getInstance().getFacetIdMapper().size(); i++)
    {
        if (tags.getTag(i) > 0)
        {
            std::map<unsigned, dynamic_bitset<>*>::const_iterator itFacet = _facetHintMaskMap.find(i);
            assert(itFacet != _facetHintMaskMap.end());

            *(itFacet->second) |= *mask;
        }
    }
}

set<ClassificationConstraints::Constraint> *
ClassAssigner::processConstraints(unsigned blockId, const Element * container)
{
    set<ClassificationConstraints::Constraint> * constraints = new set<ClassificationConstraints::Constraint>();

    const Node::NodeList constraintNodes = container->get_children("constraint");
    for (Node::NodeList::const_iterator itNode = constraintNodes.begin(); itNode != constraintNodes.end(); ++itNode)
    {
        const Element* exclude = dynamic_cast<const Element*>(*itNode);

        string constraintName = exclude->get_attribute_value("name");
        ClassificationConstraints::Constraint constraint = ClassificationConstraints::getConstraintID(constraintName);
        if (constraint == ClassificationConstraints::UNKNOWN)
        {
            CAPTOOL_MODULE_LOG_SEVERE("Unknown constraint \"" << constraintName << "\" within block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId))
            exit(-1);
        }
        constraints->insert(constraint);
    }

    return constraints;
}


void
ClassAssigner::registerPrecondition(unsigned blockId, const Element * preconditionElement)
{
    Precondition * precondition = new Precondition;

    // Create bitmask of excluded hints
    precondition->excludedHints = createExcludeMask(blockId, preconditionElement);
    dynamic_bitset<> * allowedHintsMask = createAllowMask(blockId, preconditionElement);
    // Hints also present in the allow mask are removed from the exclude mask
    *(precondition->excludedHints) &= allowedHintsMask->flip();
    delete allowedHintsMask;
    CAPTOOL_MODULE_LOG_INFO("Excluded hints mask for " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId) << ": " << *(precondition->excludedHints))

    // Read constraints
    precondition->constraints = processConstraints(blockId, preconditionElement);

    _preconditionMap.insert(std::make_pair(blockId, precondition));
}

void
ClassAssigner::registerRule(unsigned blockId, const Element * ruleElement)
{
    Rule * r = new Rule;
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();
    r->isFinal = ruleElement->get_attribute_value("final").compare("true") == 0;
    r->includedHints = createIncludeMask(blockId, ruleElement);
    r->excludedHints = createExcludeMask(blockId, ruleElement);
    r->tags = cmd.readTags(ruleElement);
    dynamic_bitset<> * allowedHintsMask = createAllowMask(blockId, ruleElement);
    // Hints also present in the allow mask are removed from the exclude mask
    *(r->excludedHints) &= allowedHintsMask->flip();
    delete allowedHintsMask;

    if ((*(r->includedHints) & *(r->excludedHints)).any())
    {
        CAPTOOL_MODULE_LOG_WARNING("Conflicting exclude and include masks within block " << cmd.getBlockIdMapper().getName(blockId) << ", removing conflicting flags from exclude mask")
        // Hints also present in the include mask are removed from the exclude mask
        *(r->excludedHints) &= ~*(r->includedHints);
    }

    // Read constraints
    r->constraints = processConstraints(blockId, ruleElement);

    _ruleMap.insert(std::make_pair(blockId, r));
    CAPTOOL_MODULE_LOG_INFO((r->isFinal ? "final " : "") << "rule for " << cmd.getBlockIdMapper().getName(blockId))
    CAPTOOL_MODULE_LOG_INFO("\texclude mask: " << *(r->excludedHints));
    CAPTOOL_MODULE_LOG_INFO("\tinclude mask: " << *(r->includedHints));
}

dynamic_bitset<> * 
ClassAssigner::createExcludeMask(unsigned blockId, const Element * container)
{
    // Read hint mask of the block
    map<unsigned, dynamic_bitset<> *>::const_iterator it = _blockHintMaskMap.find(blockId);
    dynamic_bitset<> blockHintMask = it == _blockHintMaskMap.end() ?  dynamic_bitset<>(_numberOfHints) : dynamic_bitset<>(*(it->second));

    // Mask for hints which prevent the flow to be classified for this app
    dynamic_bitset<> * excludedHintsMask = new dynamic_bitset<>(_numberOfHints);

    // Read exlude elements from the XML
    const Node::NodeList excludes = container->get_children("exclude");
    for (Node::NodeList::const_iterator itNode = excludes.begin(); itNode != excludes.end(); ++itNode)
    {
        const Element* exclude = dynamic_cast<const Element*>(*itNode);
        
        string excludedBlock = exclude->get_attribute_value("block");
        
        if (excludedBlock.compare("all") == 0)
        {
            string facetName = exclude->get_attribute_value("facet");
            if (facetName == "")
            {
                // Set all bits in the exclude mask
                excludedHintsMask->set();
                // Any further exclude rules can be ignored
                break;
            }
            else
            {
                // If a facet attribute is also specified, than only filter on blocks where a tag is defined for this facet
                unsigned facetId = ClassificationMetadata::getInstance().getFacetIdMapper().getId(facetName);
                if (facetId == (unsigned)-1)
                {
                    CAPTOOL_MODULE_LOG_SEVERE("Reference to unknown facet \"" << facetName << "\" in the precondition or rule list of " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId));
                    exit(-1);
                }
                it = _facetHintMaskMap.find(facetId);
                if (it == _facetHintMaskMap.end())
                {
                    CAPTOOL_MODULE_LOG_SEVERE("Facet hint mask not found for facet " << facetName);
                    exit(-1);
                }
                *excludedHintsMask |= *(it->second);
                continue;
            }
        }
        
        unsigned excludedBlockId = ClassificationMetadata::getInstance().getBlockIdMapper().getId(excludedBlock);
        if (excludedBlockId == unsigned(-1))
        {
            CAPTOOL_MODULE_LOG_SEVERE("Reference to unknown block \"" << excludedBlock << "\" in the precondition or rule list of " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(blockId));
            exit(-1);
        }
        it = _blockHintMaskMap.find(excludedBlockId);
        if (it == _blockHintMaskMap.end())
        {
            CAPTOOL_MODULE_LOG_SEVERE("Block hint mask not found for excluded block " << ClassificationMetadata::getInstance().getBlockIdMapper().getName(excludedBlockId));
            exit(-1);
        }
        
        *excludedHintsMask |= *(it->second);
    }
    
    // Mask out hints of this block by the complement of block hint mask
    *excludedHintsMask &= dynamic_bitset<>(blockHintMask).flip();
    
    return excludedHintsMask;
}

dynamic_bitset<> * 
ClassAssigner::createAllowMask(unsigned blockId, const Element * container)
{
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();
    
    // Mask for hints which may be present even if a general exclude tag puts them on the exclude list
    dynamic_bitset<> * allowedHintsMask = new dynamic_bitset<>(_numberOfHints);

    // Read exlude elements from the XML
    const Node::NodeList allows = container->get_children("allow");
    for (Node::NodeList::const_iterator itNode = allows.begin(); itNode != allows.end(); ++itNode)
    {
        const Element* allow = dynamic_cast<const Element*>(*itNode);
        
        string allowedBlock = allow->get_attribute_value("block");
        
        unsigned allowedBlockId = cmd.getBlockIdMapper().getId(allowedBlock);
        if (allowedBlockId == unsigned(-1))
        {
            CAPTOOL_MODULE_LOG_SEVERE("Reference to unknown block \"" << allowedBlock << "\" in the precondition or rule list of " << cmd.getBlockIdMapper().getName(blockId));
            exit(-1);
        }
        map<unsigned, dynamic_bitset<> *>::const_iterator it = _blockHintMaskMap.find(allowedBlockId);
        if (it == _blockHintMaskMap.end())
        {
            CAPTOOL_MODULE_LOG_SEVERE("Block hint mask not found for allowed block " << cmd.getBlockIdMapper().getName(allowedBlockId));
            exit(-1);
        }
        
        *allowedHintsMask |= *(it->second);
    }
    
    return allowedHintsMask;
}

dynamic_bitset<> * 
ClassAssigner::createIncludeMask(unsigned blockId, const Element * container)
{
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();
    
    // Mask for simultaneously required hints
    dynamic_bitset<> * includedHintsMask = new dynamic_bitset<>(_numberOfHints);

    // Read exlude elements from the XML
    const Node::NodeList includes = container->get_children("include");
    for (Node::NodeList::const_iterator itNode = includes.begin(); itNode != includes.end(); ++itNode)
    {
        const Element* include = dynamic_cast<const Element*>(*itNode);
        
        string includedBlock = include->get_attribute_value("block");
        string includedSig = include->get_attribute_value("sigId");
        unsigned includedBlockId;
        unsigned includedSigId;
        
        std::istringstream(includedSig) >> includedSigId;
        
        if (includedBlock == "")
        {
            // Default blockId is the container block
            includedBlockId = blockId;
        }
        else 
        {
            includedBlockId = cmd.getBlockIdMapper().getId(includedBlock);
            if (includedBlockId == unsigned(-1))
            {
                CAPTOOL_MODULE_LOG_SEVERE("Reference to unknown block \"" << includedBlock << "\" in the rule list of " << cmd.getBlockIdMapper().getName(blockId));
                exit(-1);
            }
        }
        
        // lookup position of corresponding hint
        Hintable::Hint hint = std::make_pair(includedBlockId, includedSigId);
        map<Hintable::Hint, unsigned>::const_iterator it = _hintPositionMap.find(hint);
        if (it == _hintPositionMap.end())
        {
            CAPTOOL_MODULE_LOG_SEVERE("Position of hint " << cmd.getBlockIdMapper().getName(includedBlockId) << "," << includedSigId << " not found in hint position map");
            exit(-1);
        }
        
        includedHintsMask->set(it->second);
    }
    
    return includedHintsMask;
}

bool
ClassAssigner::evaluateConstraints(const set<ClassificationConstraints::Constraint> * constraints, CaptoolPacket * captoolPacket)
{
    for (set<ClassificationConstraints::Constraint>::const_iterator itConstraint = constraints->begin(); itConstraint != constraints->end(); ++itConstraint)
    {
        if (!ClassificationConstraints::evaluateConstraint(*itConstraint, captoolPacket))
        {
            return false;
        }
    }

    return true;
}


Module*
ClassAssigner::process(CaptoolPacket* captoolPacket)
{
    assert(captoolPacket != 0);
    
    CAPTOOL_MODULE_LOG_FINEST("processing packet.")
    
    ClassificationMetadata & cmd = ClassificationMetadata::getInstance();
    
    Flow * flow = captoolPacket->getFlow().get();
    if (!flow)
    {
        CAPTOOL_MODULE_LOG_WARNING("No flow associated with packet (no. " << captoolPacket->getPacketNumber() << ")");
        return _outDefault;
    }

    if (flow->getLastHintedPacketNumber() < flow->getUploadPackets() + flow->getDownloadPackets())
    {
        // No new hints registered when processing this packet, no need to evaluate flow classification again
        return _outDefault;
    }

    dynamic_bitset<> previousFacetMask = flow->getDefinedFacets();
    dynamic_bitset<> newFacetMask(previousFacetMask.size());
    
    // Create the bitmap representation of hints and create the list of all hinted blocks
    Hintable::HintContainer hints = flow->getHints();
    dynamic_bitset<> hintMask(_numberOfHints);
    set<unsigned> hintedBlocks;
    for (Hintable::HintContainer::const_iterator itHint = hints.begin(); itHint != hints.end(); ++itHint)
    {
        // Find out hint position within the bitmap
        map<Hintable::Hint, unsigned>::const_iterator it = _hintPositionMap.find(itHint->first);
        if (it == _hintPositionMap.end())
        {
            CAPTOOL_MODULE_LOG_WARNING("Hint " << cmd.getBlockIdMapper().getName(itHint->first.first) << "," << itHint->first.second << " not found in hintPositionMap")
            continue;
        }
        hintMask.set(it->second);
        hintedBlocks.insert(it->first.first);
    }
    
    // Go through all hinted blocks
    for (set<unsigned>::const_iterator itBlock = hintedBlocks.begin(); itBlock != hintedBlocks.end(); ++itBlock)
    {
        // check preconditions
        map<unsigned, Precondition*>::const_iterator itPreconditions = _preconditionMap.find(*itBlock);
        if (itPreconditions != _preconditionMap.end())
        {
            Precondition * precondition = itPreconditions->second;
            // Check exclude mask
            if ((hintMask & *(precondition->excludedHints)).any()) continue;
            // Check constraints
            if (!evaluateConstraints(precondition->constraints, captoolPacket)) continue;
        }
        
        // look for standalone hints at this block (which can be used as implied rules)
        map<unsigned, dynamic_bitset<>*>::const_iterator itBlockHintMask = _blockHintMaskMap.find(*itBlock);
        if (itBlockHintMask == _blockHintMaskMap.end())
        {
            CAPTOOL_MODULE_LOG_SEVERE("Block hint mask not found for " << cmd.getBlockIdMapper().getName(*itBlock))
            exit(-1);
        }
        dynamic_bitset<> standaloneBlockHints(hintMask & *(itBlockHintMask->second) & *_standaloneHints);
        if (standaloneBlockHints.any())
        {
            bool isFinal = (standaloneBlockHints & *_finalHints).any();
            // Set block tags
            newFacetMask |= setTags(flow, *itBlock, isFinal, cmd.getBlock(*itBlock)->getTags());
            // Set signature specific tags (if any)
            dynamic_bitset<> taggedBlockHints(standaloneBlockHints & *_taggedHints);
            if (taggedBlockHints.any())
            {
                for (unsigned pos = taggedBlockHints.find_first(); pos != dynamic_bitset<>::npos; pos = taggedBlockHints.find_next(pos))
                {
                    map<unsigned,TagContainer>::const_iterator it = _hintTagMap.find(pos);
                    if (it == _hintTagMap.end())
                    {
                        CAPTOOL_MODULE_LOG_SEVERE("Entry " << pos << " not found in hint tag map")
                        exit(-1);
                    }
                    newFacetMask |= setTags(flow, *itBlock, _finalHints->test(pos), it->second);
                }
            }
        }
        
        // Go through rules for this app
        std::pair<multimap<unsigned, Rule*>::const_iterator, multimap<unsigned, Rule*>::const_iterator> itPair = _ruleMap.equal_range(*itBlock);
        for (multimap<unsigned, Rule*>::const_iterator itRule = itPair.first; itRule != itPair.second; ++itRule)
        {
            Rule * rule = itRule->second;
            // check exclude rules
            if ((hintMask & *(rule->excludedHints)).any()) continue;
            // check include rules
            if ((hintMask & *(rule->includedHints)) != *(rule->includedHints)) continue;
            // Check constraints
            if (!evaluateConstraints(rule->constraints, captoolPacket)) continue;
            // Both include, exclude rules and constraints satisfied -> set tags
            // Set block tags
            newFacetMask |= setTags(flow, *itBlock, rule->isFinal, cmd.getBlock(*itBlock)->getTags());
            // Set extra, rule-specific tags (if any)
            if (!rule->tags.isEmpty())
            {
                newFacetMask |= setTags(flow, *itBlock, rule->isFinal, rule->tags);
            }
        }
    }

    // Reset tags that have been invalidates since last time
    dynamic_bitset<> invalidatedFacets = (previousFacetMask ^ newFacetMask) & previousFacetMask;
    if (invalidatedFacets.any())
    {
        for (unsigned i=1; i < invalidatedFacets.size(); i++)
        {
            if (invalidatedFacets.test(i))
            {
                flow->setTag(i, (unsigned)0, false);
            }
        }
    }
    
    return _outDefault;
}

dynamic_bitset<>
ClassAssigner::setTags(Flow * flow, unsigned blockId, bool isFinal, const TagContainer& tags)
{
    flow->setTags(tags, blockId, isFinal);
    return tags.getDefinedFacets();
}

