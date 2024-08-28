/*
 * Hintable.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __HINTABLE_H__
#define __HINTABLE_H__

#include <map>
#include <ostream>

using std::string;

/**
 * Stores hints for an object. Hints are defined in a two dimensional ID space:
 * block_id and hint_id within the block. For efficiency, both are represented
 * as unsigned integers. Mutiple hints of the same kind can be specified and
 * the Hintable class stores the number of occurences for each of these hints.
 */
class Hintable
{
    public:
        
        /**
         * Constructor.
         */
        Hintable();

        /**
         * Destructor.
         */
        ~Hintable();
        
        /**
         * Type of classification hints. Hints are defined in a two dimensional ID space:
         * block_id and hint_id within the block. Both are unsigned integers.
         */
        typedef std::pair<unsigned, unsigned> Hint;
        
        /** Type of hint containers. Maps hints to the number of their occurences */
        typedef std::map<Hint, unsigned> HintContainer;
        
        /**
         * Set a hint about this object. 
         *
         * @param blockId identifier of the block in which the hint had been defined
         * @param hintId identifier of the hint within the block
         * @return true if this was the first occurence of the hint andreturn false if the same hint had already been registered before.
         */
        virtual bool setHint(unsigned blockId, unsigned hintId);
        
        /**
         * Return the container of all hints placed on the object.
         *
         * @return the whole container
         */
        const HintContainer& getHints() const;
        
    private:
        
        /** map of class identifier hints */
        HintContainer   hints;

        /**
         * Print hints in in the following format: hints={(block_name,hint_id,no_of_occurences), (block_name,hint_id,no_of_occurences),...}
         */
        friend std::ostream& operator<<(std::ostream& o, const Hintable& h);
};

#endif // header file
