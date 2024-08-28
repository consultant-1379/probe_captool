/*
 * ClassifierDescriptor.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CLASSIFIER_DESCRIPTOR_H__
#define __CLASSIFIER_DESCRIPTOR_H__

#include <libxml++/libxml++.h>

using xmlpp::Element;

class ClassifierDescriptor
{
    public:
        
        ClassifierDescriptor(unsigned id, bool standalone, bool final);
    
        unsigned getId() const;
        
        bool isStandalone() const;
        
        bool isFinal() const;
        
    private:

        unsigned _sigId;
        bool _standalone;
        bool _final;
};

inline
ClassifierDescriptor::ClassifierDescriptor(unsigned sigId, bool standalone, bool final)
    :   _sigId(sigId),
        _standalone(standalone),
        _final(final)
{
}

inline unsigned
ClassifierDescriptor::getId() const
{
    return _sigId;
}

inline bool
ClassifierDescriptor::isStandalone() const
{
    return _standalone;
}

inline bool
ClassifierDescriptor::isFinal() const
{
    return _final;
}

#endif // __CLASSIFIER_DESCRIPTOR_H__
