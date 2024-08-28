/*
 * FacetClassified.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __FACET_CLASSIFIED_H__
#define __FACET_CLASSIFIED_H__

#include "TagContainer.h"

#include <boost/dynamic_bitset.hpp>
#include <sstream>
#include <set>

using boost::dynamic_bitset;
using std::string;
using std::set;

/**
 * Allows classification of an object along different (typically orthogonal) facets.
 * Each facet (tag) defines a non-overlaping set of tag values and one of
 * these values can be assigned to the object. A tag value cannot be interpreted
 * standalone, it is always coupled to the name or the ID of the tag.
 */
class FacetClassified
{
    public:
        
        /**
         * Constructor.
         */
        FacetClassified();

        /**
         * Destructor.
         */
        ~FacetClassified();
        
        /**
         * Set a new tag for this object. If a final tagValue had already been registerd, 
         * then this new tag is ignored.
         *
         * @param tagId the ID of the tag to be assigned
         * @param tagValue the value to be assigned for the given tag
         */
        void setTag(unsigned tagId, unsigned tagValue, bool final);
        
        /**
         * Attempts to update all tags set by a given classification block
         *
         * @param newTags the TagContainer with new tag values to be used for the update. Note that undefined tags in newTags are ignored.
         * @blockId the ID of the classification block for which tags are set
         * @param final the final flag to be applied when updating all individual tags
         */
        virtual void setTags(const TagContainer& newTags, unsigned blockId, bool final);
        
        /**
         * Return the value of the given tag.
         *
         * @param tagId the ID of the tag whose value is queried
         * @return the value of the tag as an unsigned, or zero if no such tag is specified.
         */
        unsigned getTag(unsigned tagId) const;
        
        /**
         * Return tag container.
         */
        const TagContainer& getTags() const;
        
        /**
         * Return the set of block IDs tagged as final
         */
        const set<unsigned>& getFinalBlockIds() const;
        
        /**
         * Tell whether a tag is set as final.
         *
         * @param tag the ID of the tag whose status is queried
         */
        bool isFinal(unsigned tagId) const;
        
        /**
         * Tells whether all required facets have a final tag.
         *
         * @return true if all required facets are set and are final; returns false otherwise.
         */
        bool isFinal() const;

        /** 
         * Returns a bitmap, where the ith flag is set if the ith facet had been assigned a valid tag 
         */
        dynamic_bitset<> getDefinedFacets() const;
        
    private:
        
        /** Stores tags */
        TagContainer _tags;
        
        /** Stores final/not-final flags for each tag */
        dynamic_bitset<> _finalFlags;
        
        /** The set of classification block IDs for which final tags had been set */
        set<unsigned> _finalBlockIds;
        
        /** Stores cached final state */
        mutable bool _cachedFinalState;
        
        /** Indicates whether the cached final state is valid or has already been invalidated */
        mutable bool _cachedFinalStateValid;

        /** Print tags in in the following format: tags={facet_name.focus_name,facet_name.focus_name,...} */
        friend std::ostream& operator<<(std::ostream&, const FacetClassified&);
};

inline unsigned
FacetClassified::getTag(unsigned tagId) const
{
    return _tags.getTag(tagId);
}

inline const TagContainer&
FacetClassified::getTags() const
{
    return _tags;
}

inline const set<unsigned>&
FacetClassified::getFinalBlockIds() const
{
    return _finalBlockIds;
}

inline bool
FacetClassified::isFinal(unsigned tagId) const
{
    return _finalFlags.test(tagId);
}

inline dynamic_bitset<>
FacetClassified::getDefinedFacets() const
{
    return _tags.getDefinedFacets();
}

#endif // header file
