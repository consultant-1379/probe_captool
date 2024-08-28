/*
 * CaptoolPacketProtocol.h -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#ifndef __CAPTOOL_PACKET_PROTOCOL_H__
#define __CAPTOOL_PACKET_PROTOCOL_H__

#include <sys/types.h>

namespace captool {

class Module;    
class CaptoolPacket;

/**
 * Structure representing a protocol in CaptoolPacket 's protocol stack
 */
class CaptoolPacketProtocol
{
    public:
        /**
         * Constructor.
         */
        CaptoolPacketProtocol();
        
        /**
         * Resets the protocol.
         */
        void reset();
        
        /**
         * Resets the protocol based on the given input.
         *
         * @param module owner Module of the protocol
         * @param pointer pointer to the protocol in the packet
         * @param length the length of the protocol
         * @param payloadLength the length of the payload of the protocol
         * @param valid validity of the protocol header
         */
        void reset(Module *module, const u_char *pointer, u_int length, u_int payloadLength, bool valid);
        
        /**
         * Returns a pointer to this protocol and its length
         *
         * @param length location where the length of the protocol is to be copied
         *
         * @return pointer to this protocol
         */
        const u_char * get(size_t *length) const;
        
        /**
         * Returns a pointer to this protocol and its length including its payload
         *
         * @param length location where the length of the protocol with its payload is to be copied
         *
         * @return pointer to this protocol
         */
        const u_char * getWithPayload(u_int *length) const;
        
    private:

        /** the owner Module of the protocol */
        Module*       _module;
        
        /** pointer to the header */
        const u_char* _pointer;
        
        /** length of the header */
        u_int         _length;
        
        /** length of its total payload */
        u_int         _payloadLength;
        
        /** validity of the header (invalidated by payload changes) */
        bool          _valid;

        friend class CaptoolPacket;
    
        
};

inline
CaptoolPacketProtocol::CaptoolPacketProtocol()
    : _module(0),
      _pointer(0),
      _length(0),
      _payloadLength(0),
      _valid(false)
{
}

inline void
CaptoolPacketProtocol::reset()
{
    _module = 0;
    _pointer = 0;
    _length = 0;
    _payloadLength = 0;
    _valid = false;
}
    
inline void
CaptoolPacketProtocol::reset(Module *module, const u_char *pointer, u_int length, u_int payloadLength, bool valid)
{
    _module = module;
    _pointer = pointer;
    _length = length;
    _payloadLength = payloadLength;
    _valid = valid;
}

inline const u_char *
CaptoolPacketProtocol::get(size_t *length) const
{
    if (length != 0)
    {
        *length = _length;
    }
    return _pointer;
}

inline const u_char *
CaptoolPacketProtocol::getWithPayload(u_int *length) const
{
    if (length != 0)
    {
        *length = _length + _payloadLength;
    }
    return _pointer;
}

} // namespace captool
    
#endif // __CAPTOOL_PACKET_PROTOCOL_H__
