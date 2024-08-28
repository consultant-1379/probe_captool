/*
 * ClassificationConstraints.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CLASSIFICATION_CONSTRAINTS_H__
#define __CLASSIFICATION_CONSTRAINTS_H__

#include <string>

#include "captoolpacket/CaptoolPacket.h"

using captool::CaptoolPacket;

using std::string;

/**
 * Evaluate constraints which are required in order to tag a flow in addition to hints.
 * A classification constraint typically cannot be used standalone as a hint but only
 * as an additional cross check for other hints. E.g. RTP sequence number tracking provides
 * good hints for the RTP protocol but is not sufficient to tag a flow as RTP. However,
 * applying a constraint on some RTP header bit, classification becomes pretty reliable.
 * The constraint construct is necessary, because a hint for those flags would match too much
 * other traffic polluting unnecessary flow log and reducing classification performance.
 */
class ClassificationConstraints
{
    public:

        /**  Uniquely identifies a constraint construct */
        enum Constraint
        {
            UNKNOWN,
            RTP_HEADER,
            UNIDIRECTIONAL_FLOW,
            SYMMETRIC_FLOW,
            FIRST_UL_PACKET,
            FIRST_DL_PACKET
        };

        /**
         * Maps constraint name to constraint ID.
         *
         * @param the name of the constraint which is used in the classification XML
         * @return the ID of the constraint which is used internally in classification modules
         */
        static Constraint getConstraintID(string constraintName);

        /**
         * Evaluate a constraint for a given packet and its associated flow
         *
         * @param constraintID the ID of the constrinat to be evaluated
         * @param packet the CaptoolPacket and its associated flow to be evaluated
         * @return true if the constraint holds and false if it fails
         */
        static bool evaluateConstraint(Constraint constraintID, const CaptoolPacket * packet);

    private:

        /** Returns true if RTP header seems to be OK */
        static bool evaluateRtpFlags(const u_char * payload, u_int payloadLength);

        /** Returns true if the flow seems to be a unidirectional flow */
        static bool evaluateUnidirectionalFlow(const Flow * flow);

        /** Returns true if the flow seems to be a symmetric bidirectional flow. E.g. for VOIP */
        static bool evaluateSymmetricFlow(const Flow * flow);
};

#endif // header
