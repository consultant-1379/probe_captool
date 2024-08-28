/*
 * Signature.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __SIGNATURE_H__
#define __SIGNATURE_H__

#include "TagContainer.h"

#include <libxml++/libxml++.h>
#include "util/log.h"

using xmlpp::Element;

class Signature
{
    public:
        
        Signature(const Signature& signature);
        
        Signature(unsigned id, bool standalone, bool final, const Element * xmlDefinition, const TagContainer& tags);
        
        ~Signature();
    
        unsigned getId() const;
        
        bool isStandalone() const;
        
        bool isFinal() const;
        
        const Element * getXmlDefinition() const;
        
        const TagContainer& getTags() const;
    
    private:

        unsigned _sigId;
        bool _standalone;
        bool _final;
        const Element * _xmlDefinition;
        TagContainer _tags;
};

inline
Signature::Signature(unsigned sigId, bool standalone, bool final, const Element * xmlDefinition, const TagContainer& tags)
    :   _sigId(sigId),
        _standalone(standalone),
        _final(final),
        _xmlDefinition(xmlDefinition),
        _tags(tags)
{
}

inline
Signature::Signature(const Signature& signature)
    :   _sigId(signature._sigId),
        _standalone(signature._standalone),
        _final(signature._final),
        _xmlDefinition(signature._xmlDefinition),
        _tags(signature._tags)
{
    CAPTOOL_LOG_WARNING("Signature copy constructor, sigId=" << _sigId)
}

inline
Signature::~Signature()
{
}

inline unsigned
Signature::getId() const
{
    return _sigId;
}

inline bool
Signature::isStandalone() const
{
    return _standalone;
}

inline bool
Signature::isFinal() const
{
    return _final;
}

inline const Element *
Signature::getXmlDefinition() const
{
    return _xmlDefinition;
}

inline const TagContainer&
Signature::getTags() const
{
    return _tags;
}


#endif // __SIGNATURE_H__
