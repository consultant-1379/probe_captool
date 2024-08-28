/*
 * TagContainer.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __TAG_CONTAINER_H__
#define __TAG_CONTAINER_H__

#include <boost/dynamic_bitset.hpp>
#include <vector>

using boost::dynamic_bitset;

class FacetClassified;

class TagContainer 
{
    public:
    
        TagContainer();

        TagContainer(size_t size);
        
        TagContainer(const TagContainer& tagContainer);
        
        ~TagContainer();
        
        /**
         * Set a new tag value for the specified facet
         *
         * @param tagId the ID of the tag to be assigned
         * @param tagValue the value to be assigned for the given tag
         */
        void setTag(unsigned tagId, unsigned tagValue);

        /**
         * Return the value of the given tag.
         *
         * @param tagId the ID of the tag whose value is queried
         * @return the value of the tag as an unsigned, or zero if no such tag is specified.
         */
        unsigned getTag(unsigned tagId) const;
        
        /** 
         * Returns a bitmap, where the ith flag is set if the ith facet had been assigned a valid tag 
         */
        dynamic_bitset<> getDefinedFacets() const;
        
        /**
         * Tests whether this TagContainer object holds the same tag values than the other one.
         *
         * @param o the other TagContainer object to compare with
         * @return true if all tags in both objects hold the same value, false otherwise
         */
        bool equals(const TagContainer &o) const;
        
        /** Returns the total number of possible facets */
        size_t size() const;
        
        /** Returns true if none of the tags are defined within this container */
        bool isEmpty() const;
        
        /**
         * Returns a hash code of this object
         */
        size_t hashCode() const;
        
        /** Return string representation */
        std::string str() const;
    
    private:

        /** 
         * Stores tags. The ith element of the vector stores the value of the ith tag. 
         */
        std::vector<unsigned> tags;

        /** Total number of possible tags. Note that the size of the underlaying vector is +1 since tagId numbering starts at 1 */
        size_t _size;
        
        /** Set to 1 for each facetId for which a tag has been defined */
        dynamic_bitset<> _definedFacets;
        
        /** Hash code of this object as calculated last time */
        mutable std::size_t    hash;
        
        /** String representation as calculated last time */
        mutable std::string    repr;
        
        /** True if none of the tags is specified */
        mutable bool           empty;
        
        /** Flags that hash code and string representation needs recalculation.
         * @note Should be set by every method that changes tag values
         */
        mutable bool           dirty;
        
        /** Update hash and string representation */
        void  update() const;
};

inline unsigned
TagContainer::getTag(unsigned tagId) const
{
    return tags[tagId];
}

inline void
TagContainer::setTag(unsigned tagId, unsigned tagValue)
{
    _definedFacets.set(tagId, tagValue > 0);
    tags[tagId] = tagValue;
    dirty = true;
}

inline dynamic_bitset<>
TagContainer::getDefinedFacets() const
{
    return _definedFacets;
}


inline size_t
TagContainer::size() const
{
    return _size;
}

#endif // header file
