/*
 * SequenceNumberData.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __SEQUENCE_NUMBER_DATA_H__
#define __SEQUENCE_NUMBER_DATA_H__

#include "captoolpacket/CaptoolPacket.h"

using captool::CaptoolPacket;

/** Tracks sequence numbers within a flow */
class SequenceNumberData : public Parameter
{
    public:

        /** Constructor */
        SequenceNumberData();

        /** Destructor */
        ~SequenceNumberData();

        /**
         * Updates Sequence number statistics.
         *
         * @param currentSequenceNumber the sequence number in the latest packet
         * @return the number of subsequent packets (either in UL or DL) with strictly increasing sequence numbers.
         */
        unsigned update(unsigned long currentSequenceNumber, CaptoolPacket::Direction direction);

    private:

        /** Latest sequence number within flow */
        unsigned long   _lastSequenceNumber;

        /** Latest sequence number within flow for UL */
        unsigned long   _lastSequenceNumberUL;

        /** Latest sequence number within flow for DL */
        unsigned long   _lastSequenceNumberDL;

        /** Number of subsequent packets with regularly increasing sequence numbers */
        unsigned    _subsequentSequenceNumbers;

        /** Number of subsequent packets with regularly increasing sequence numbers for UL packets */
        unsigned    _subsequentSequenceNumbersUL;

        /** Number of subsequent packets with regularly increasing sequence numbers for DL packets */
        unsigned    _subsequentSequenceNumbersDL;
};

inline
SequenceNumberData::SequenceNumberData()
    :   _lastSequenceNumber(0),
        _lastSequenceNumberUL(0),
        _lastSequenceNumberDL(0),
        _subsequentSequenceNumbers(0),
        _subsequentSequenceNumbersUL(0),
        _subsequentSequenceNumbersDL(0)
{
}

inline
SequenceNumberData::~SequenceNumberData()
{
}

inline
unsigned
SequenceNumberData::update(unsigned long currentSequenceNumber, CaptoolPacket::Direction direction)
{
    if (direction == CaptoolPacket::DOWNLINK)
    {
        if (currentSequenceNumber == _lastSequenceNumberDL + 1)
        {
            _subsequentSequenceNumbersDL++;
        }
        else
        {
            _subsequentSequenceNumbersDL = 0;
        }

        _lastSequenceNumberDL = currentSequenceNumber;
        return _subsequentSequenceNumbersDL;
    }
    else if (direction == CaptoolPacket::UPLINK)
    {
        if (currentSequenceNumber == _lastSequenceNumberUL + 1)
        {
            _subsequentSequenceNumbersUL++;
        }
        else
        {
            _subsequentSequenceNumbersUL = 0;
        }

        _lastSequenceNumberUL = currentSequenceNumber;
        return _subsequentSequenceNumbersUL;
    }
    else
    {
        // In case the used configuration does not provide traffic direction information
        if (currentSequenceNumber == _lastSequenceNumber + 1)
        {
            _subsequentSequenceNumbers++;
        }
        else
        {
            _subsequentSequenceNumbers = 0;
        }

        _lastSequenceNumber = currentSequenceNumber;
        return _subsequentSequenceNumbers;
    }
}

#endif // header
