/*
 * Classifier.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include "classification/Classifier.h"

Classifier::Classifier()
{
    if (!ClassificationMetadata::getInstance().isInitialized())
    {
        CAPTOOL_LOG_SEVERE("Classification metadata not initialized, unable to load classification modules")
        exit(-1);
    }
}

void
Classifier::registerSignatures(const string type)
{
    for (unsigned blockId = 1; blockId <= ClassificationMetadata::getInstance().getBlockIdMapper().size(); blockId++)
    {
        const ClassificationBlock * block = ClassificationMetadata::getInstance().getBlock(blockId);
        
        pair<ClassificationBlock::SignatureIterator,ClassificationBlock::SignatureIterator> iteratorPair = block->getSignatureIterators(type);
        for (ClassificationBlock::SignatureIterator it = iteratorPair.first; it != iteratorPair.second; ++it)
        {
            registerSignature(blockId, it->second);
        }
    }
}

