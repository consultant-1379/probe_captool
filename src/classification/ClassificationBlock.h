/*
 * ClassificationBlock.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CLASSIFICATION_BLOCK_H__
#define __CLASSIFICATION_BLOCK_H__

#include <libxml++/libxml++.h>

#include <string>
#include <vector>
#include <map>

#include "Signature.h"
#include "TagContainer.h"
#include "util/log.h"

using std::string;
using std::pair;
using std::vector;
using std::multimap;
using xmlpp::Element;

class ClassificationBlock
{
    public:
        
        ClassificationBlock(const TagContainer& tags, const Element * preconditions = NULL);
        
        ~ClassificationBlock();

        void addSignature(const Signature * signature);
        
        void addRule(const Element * ruleElement);
        
        typedef multimap<string,const Signature*>::const_iterator SignatureIterator;
        
        const TagContainer& getTags() const;
        
        /** 
         * Returns a pair of iterators that can be used to walk through signatures of this block.
         *
         * @param type signature types to filter on. If not specified, than iterators will walk through all signatures regardless of type
         */
        pair<SignatureIterator,SignatureIterator> getSignatureIterators(const string type = "") const;
        
        const Element * getPreconditions() const;
        
        const vector<const Element *>& getRules() const;
        
    private:
    
        /** Tags associated to this block */
        TagContainer _tags;
        
        /** Contains signatures defined within this block (mapped to signature type) */
        multimap<string, const Signature*> _signatures;
        
        /** Pointer to XML element defining preconditions for this block (or null if no preconditions had been defined) */
        const Element * _preconditions;
        
        /** Rules defined within this block */
        vector<const Element *> _rules;
};

inline
ClassificationBlock::ClassificationBlock(const TagContainer& tags, const Element * preconditions)
    :   _tags(tags),
        _preconditions(preconditions)
{
}

inline
ClassificationBlock::~ClassificationBlock ()
{
    for (multimap<string, const Signature*>::const_iterator i = _signatures.begin(); i != _signatures.end(); ++i)
        delete i->second;
}

inline void
ClassificationBlock::addSignature(const Signature * signature)
{
    string type = signature->getXmlDefinition()->get_name();
    _signatures.insert(std::make_pair(type, signature));
}

inline void
ClassificationBlock::addRule(const Element * ruleElement)
{
    _rules.push_back(ruleElement);
}

inline const TagContainer&
ClassificationBlock::getTags() const
{
    return _tags;
}

inline pair<ClassificationBlock::SignatureIterator,ClassificationBlock::SignatureIterator>
ClassificationBlock::getSignatureIterators(const string type) const
{
    return type == "" ? std::make_pair(_signatures.begin(), _signatures.end()) : _signatures.equal_range(type);
}

inline const Element *
ClassificationBlock::getPreconditions() const
{
    return _preconditions;
}

inline const vector<const Element *>&
ClassificationBlock::getRules() const
{
    return _rules;
}

#endif