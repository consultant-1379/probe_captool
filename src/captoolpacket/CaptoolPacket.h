/*
 * CaptoolPacket.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CAPTOOL_PACKET_H__
#define __CAPTOOL_PACKET_H__

#include <iostream>
#include <sstream>
#include <queue>
#include <pcap.h>
#include <sys/types.h>
#include <time.h>

#include "util/AutoMem.h"
#include "util/log.h"
#include "modulemanager/Module.h"
#include "flow/FlowID.h"
#include "userid/ID.h"
#include "flow/Flow.h"
#include "CaptoolPacketProtocol.h"

namespace captool
{

class Module;    

/**
 * Represents the state of the current packet being processed by the modules.
 * Can be reused by reinitializing its values.
 */
class CaptoolPacket
{
    public:

        /**
         * Constructor.
         */
        CaptoolPacket();
        
        /**
         * Destructor
         */
        ~CaptoolPacket();
	
        /** Direction of the packet */
        enum Direction {
            UNDEFINED_DIRECTION,
            UPLINK,
            DOWNLINK
        };

        /**
         * Initializes the CaptoolPacket.
         *
         * @param packetNumber number of the packet in receiving order
         */    
        void initialize(u_int packetNumber);
        
        /**
         * Resets the packet.
         */
        void reset();
        
        /**
         * Returns the pcap header of the packet.
         *
         * @return pcap header
         */
        const struct pcap_pkthdr *getPcapHeader() const;

        /**
         * Returns a pointer to the content of the packet.
         *
         * @param length the location where the content length should be copied
         *
         * @return a pointer to the content of the packet
         */
        const u_char *getPayload(size_t *length) const;

        /**
         * Returns the number of packet in receivng order
         */
        u_int getPacketNumber() const;
        
        /**
         * Returns a pointer to the pointer to the pcap header of the packet.
         *
         * @return pointer to the pointer to the pcap header of the packet
         */
        struct pcap_pkthdr **getPcapHeaderPtr();
        
        /**
         * Returns a pointer to the pointer of the content of the packet.
         *
         * @return a pointer to the pointer of the content of the packet.
         */
        const u_char **getPcapPacketPtr();
        
        /**
         * Returns a pointer to the protocol of the given module.
         *
         * @param module the module
         * @param length location where the protocol's length should be copied
         *
         * @return pointer to the procotol
         */
        const u_char* getSegment(Module *module, u_int *length) const;

        /**
         * Returns the length of the payload of the given module's protocol.
         *
         * @return length of the payload
         */
        u_int32_t getSegmentsPayloadLength(Module *modue) const;
        
        /**
         * Returns the length of the the given module's protocol including its payload.
         *
         * @return length of the protocol including its payload
         */
        u_int32_t getSegmentsTotalLength(Module *module) const;
        
        /**
         * Returns the level of the current protocol stack
         *
         * @return level of the protocol stack
         */
        u_int getLevel() const;
        
        /**
         * Sets the direction of the packet
         */
        void setDirection(CaptoolPacket::Direction direction);
        
        /**
         * Returns the direction of this packet
         */
        Direction getDirection() const;
        
        /**
         * Returns the associated FlowID of the packet
         *
         * @return the FlowID
         */
        FlowID & getFlowID();

        /**
         * Associate a flow structure to the packet.
         *
         * @param flow Flow object this packet belongs to
         */
        void setFlow(Flow::Ptr flow);
        
        /**
         * Returns the flow structure associated to the packet.
         *
         * @return pointer to Flow object the packet belongs to
         */
        Flow::Ptr & getFlow();
        
        /**
         * Counterpart of getFlow() for const @c CaptoolPacket instances.
         */
        const Flow::Ptr & getFlow() const;
        
        /**
         * Sets the number of this packet in its flow
         *
         * @param flowNumber number of packet in its flow
         */
        void setFlowNumber(u_int flowNumber);
        
        /**
         * Returns the number of packet in its flow
         *
         * @return number of packet in its flow
         */
        u_int getFlowNumber() const;
        
        /**
         * Sets the user ID associated with the packet
         *
         * @param imsi the ID
         */
        void setUserID(const ID::Ptr & id);
        
        /**
         * Returns the user ID associated with the packet
         *
         * @return the associated ID
         */
        const ID::Ptr & getUserID() const;
        
        /**
         * Sets the user ID associated with the packet
         *
         * @param imsi the ID
         */
        void setEquipmentID(const ID::Ptr & id);
        
        /**
         * Returns the user ID associated with the packet
         *
         * @return the associated ID
         */
        const ID::Ptr & getEquipmentID() const;
        
        /**
         * Saves the next length bytes as the procol of the given module
         *
         * @param module the owner Module of the procotol
         * @param length the length to be saved
         */
        void saveSegment(Module* module, u_int length);
        
        /**
         * Changes the payload of the current packet
         *
         * @param payload pointer to the new payload
         * @param payloadLength length of the payload
         * @param true if changing was successful
         */
        bool changePayload(const u_char *payload, u_int payloadLength);
        
        /**
         * Changes the timestamp of the packet
         *
         * @param timestamp the new timestamp
         */     
        void changeTimestamp(struct timeval *timestamp);
        
        /**
         * Changes the state of the current packet to COPY, making a copy of the original pcap packet.
         *
         * @param copyPayload if set to true, the payload is also copied
         * @return true on success
         */
        bool makeCopy(bool copyPayload);
        
        /**
         * Describes the current packet. Used for debugging the protocol stack.
         *
         * @return the string with information on current packet
         */
        std::string describe() const;

        /**
         * Requests the packet to provide a pointer and header for the given snaplength to be dumped.
         *
         * @param baseModule the lowest protocol on the stack that is requested in the byte array, or 0 if the complete packet is requested
         * @param snapLength the length of the requested portion or 0 if the complete packet is requested
         * @param fixHeaders tells whether the headers should be fixed before dumping
         * @param header location where the header is to be provided
         * 
         * @return pointer to the byte array
         */
        const u_char *toByteArray(Module *baseModule, u_int snapLength, bool fixHeaders, pcap_pkthdr const **header);

    private:
        
        /** The state of a packet */
        enum State {PCAP,     /**< In this state the original pcap pointer is stored. */
                    COPY,     /**< In this state the original pcap pointer is copied to an own location. */
                    DEEP_COPY /**< In this state all protocols store their own copy. NOT USED. */
        };
        
        /** the current state of the CaptoolPacket */
        State             _state;
        
        /** the pcapHeader supplied by pcap */
        struct pcap_pkthdr *_pcapHeader;
        
        /** number of packet in receiving order */
        u_int             _packetNumber;
        
        /** pointer to the packet supplied by pcap, or 0 in COPY state */
        const u_char     *_pcapPacket;
        
        /** pointer to the copy of the original packet */
        AutoMem           _copyPacket;
        
        /** flow ID of the current packet */
        FlowID            _flowID;
        
        /** Direction of the packet */
        Direction         _direction;

        /** the associated user ID */
        ID::Ptr         _userID;

        /** the associated equipment ID */
        ID::Ptr         _equipmentID;
        
        /** flow object the packet belongs to */
        Flow::Ptr    _flow;
        
        /** number of packet in current flow */
        u_int             _flowNumber;
        
        /** stack of protocols */
        CaptoolPacketProtocol * _protocols;
        
        /** length reserved for the stack of protocols */
        u_int             _protocolsArrayLength;
        
        /** number of protocols in the current stack*/
        u_int             _protocolsNumber;
        
        /** pointer to the payload of the packet (part not reserved by protocols) */
        CaptoolPacketProtocol _payload;
        
        /** total length of packet reserved by protocols */
        u_int             _protocolsLength;
        
        /** fake header used when snaplength is set */
        pcap_pkthdr       _byteArrayHeader; // fake header for snaplengths
        
        
        /** default length of allocated memory for storing COPY packet */
        static const u_int CAPTOOL_PACKET_DEFAULT_COPY_LENGTH = 65536;
        
        /** default size of the protocol stack */
        static const u_int CAPTOOL_PACKET_DEFAULT_ARRAY_LENGTH = 30;

};

inline const u_char*
CaptoolPacket::getPayload(size_t* length) const
{
    return _payload.get(length);
}        

inline const struct pcap_pkthdr*
CaptoolPacket::getPcapHeader() const
{
    return _pcapHeader;
}
   
inline u_int
CaptoolPacket::getLevel() const
{
    return _protocolsNumber;
}

inline void
CaptoolPacket::saveSegment(Module* module, u_int length)
{
    assert(length <= _payload._length);
    
    assert(_protocolsNumber < _protocolsArrayLength);
    
    _protocols[_protocolsNumber].reset(module, _payload._pointer, length, _payload._length - length, true);

    ++_protocolsNumber;
    
    if (_protocolsNumber >= _protocolsArrayLength)
    {
        // resize array
        _protocolsArrayLength = _protocolsNumber * 2;
        CaptoolPacketProtocol *_newProtocols = new CaptoolPacketProtocol[_protocolsArrayLength];
        memcpy(_newProtocols, _protocols, sizeof(_protocols));
        
        delete[](_protocols);
        _protocols = _newProtocols;
    }
    
    _payload._pointer += length;
    _payload._length  -= length;

    _protocolsLength  += length;
}

inline const u_char*
CaptoolPacket::getSegment(Module* module, u_int* length) const
{
    assert(module != 0);
    
    for (u_int i=0; i<_protocolsNumber; ++i)
    {
        if (_protocols[i]._module == module)
        {
            if (length != 0)
            {
                *length = _protocols[i]._length;
            }
            return _protocols[i]._pointer;
        }
    }
    
    return 0;
}

inline void
CaptoolPacket::changeTimestamp(struct timeval *timestamp)
{
    assert (timestamp != 0);
    
    _pcapHeader->ts = *timestamp;
};

inline u_int
CaptoolPacket::getPacketNumber() const
{
    return _packetNumber;
}

inline CaptoolPacket::Direction
CaptoolPacket::getDirection() const
{
    return _direction;
}

inline void
CaptoolPacket::setDirection(CaptoolPacket::Direction direction)
{
    _direction = direction;
}

inline
FlowID &
CaptoolPacket::getFlowID()
{
    return _flowID;
}

inline
Flow::Ptr &
CaptoolPacket::getFlow()
{
    return _flow;
}

inline
const Flow::Ptr &
CaptoolPacket::getFlow() const
{
    return _flow;
}

inline void
CaptoolPacket::setFlow(Flow::Ptr flow)
{
    _flow = flow;
}

inline u_int
CaptoolPacket::getFlowNumber() const
{
    return _flowNumber;
}

inline void
CaptoolPacket::setFlowNumber(u_int flowNumber)
{
    _flowNumber = flowNumber;
}

inline 
const
ID::Ptr &
CaptoolPacket::getUserID() const
{
    return _userID;
}

inline void
CaptoolPacket::setUserID(const ID::Ptr & id)
{
    _userID = id;
}

inline 
const
ID::Ptr &
CaptoolPacket::getEquipmentID() const
{
    return _equipmentID;
}

inline void
CaptoolPacket::setEquipmentID(const ID::Ptr & id)
{
    _equipmentID = id;
}

inline struct pcap_pkthdr **
CaptoolPacket::getPcapHeaderPtr()
{
    return &_pcapHeader;
}

inline const u_char **
CaptoolPacket::getPcapPacketPtr()
{
    return &_pcapPacket;
}


inline u_int32_t
CaptoolPacket::getSegmentsPayloadLength(Module *module) const
{
    assert(module != 0);
    
    for (u_int i=0; i<_protocolsNumber; ++i)
    {
        if (_protocols[i]._module == module)
        {
            return _protocols[i]._payloadLength + (_pcapHeader->len - _pcapHeader->caplen);
        }
    }
    
    return 0;
}

inline u_int32_t
CaptoolPacket::getSegmentsTotalLength(Module *module) const
{
    assert(module != 0);
    
    for (u_int i=0; i<_protocolsNumber; ++i)
    {
        if (_protocols[i]._module == module)
        {
            return ( _protocols[i]._length + _protocols[i]._payloadLength  + (_pcapHeader->len - _pcapHeader->caplen));
        }
    }
    
    return 0;
}

} // namespace captool

#endif // __CAPTOOL_PACKET_H__
