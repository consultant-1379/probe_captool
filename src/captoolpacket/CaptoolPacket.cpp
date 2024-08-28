/*
 * CaptoolPacket.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

#include <cassert>

#include "util/log.h"

#include "CaptoolPacket.h"

using std::string;

namespace captool
{
    
CaptoolPacket::CaptoolPacket()
    : _state(PCAP),
      _pcapHeader(),
      _packetNumber(0),
      _pcapPacket(0),
      _copyPacket(CAPTOOL_PACKET_DEFAULT_COPY_LENGTH),
      _flowID(),
      _direction(CaptoolPacket::UNDEFINED_DIRECTION),
      _flowNumber(0),
      _protocols(0),
      _protocolsArrayLength(CAPTOOL_PACKET_DEFAULT_ARRAY_LENGTH),
      _protocolsNumber(0),
      _payload(),
      _protocolsLength(0),
      _byteArrayHeader()
{
    assert(_protocolsArrayLength > 0);
    
    _protocols = new CaptoolPacketProtocol[_protocolsArrayLength];
    
    assert(_protocols != 0);
}

void
CaptoolPacket::reset()
{
    _flowID.reset();
    _flowNumber = 0;
    _direction = CaptoolPacket::UNDEFINED_DIRECTION;
    _protocolsLength = 0;

    _protocolsNumber = 0;
    
    _userID.reset();
    _equipmentID.reset();
}
    
void
CaptoolPacket::initialize(u_int packetNumber)
{
    assert(_pcapPacket != 0);
    assert(_pcapHeader != 0);
    
    reset();
    _state = PCAP;
    _packetNumber = packetNumber;
    _payload.reset(0, _pcapPacket, _pcapHeader->caplen, 0, true);
};        
   
CaptoolPacket::~CaptoolPacket()
{
    delete[](_protocols);
}

bool
CaptoolPacket::makeCopy(bool copyPayload)
{
    // return if already in copy state
    if (_state == COPY || _state == DEEP_COPY)
    {
        return true;
    }

    // copy the packet with or without the payload
    if (! _copyPacket.copy(_pcapPacket, copyPayload ? _pcapHeader->caplen : (_pcapHeader->caplen - _payload._length)))
        return false;
    
    /* update all pointers */
    u_int diff = (u_char *)_copyPacket.get(0) - _pcapPacket;

    assert(diff != 0);
    
    for (u_int i=0; i<_protocolsNumber; ++i)
    {
        _protocols[i]._pointer += diff;
    }
    
    if (copyPayload)
    {
        _payload._pointer += diff;
    }
    else
    {
        //substract payload from payloadLength of all protocols
        for (u_int i=0; i<_protocolsNumber; ++i)
        {
            assert(_protocols[i]._payloadLength >= _payload._length);
            
            _protocols[i]._payloadLength -= _payload._length;
            
        }

        //reset payload
        assert(_pcapHeader->caplen >= _payload._length);
        
        _pcapHeader->caplen -= _payload._length;
        _payload.reset(0, 0, 0, 0, true);
    }

    // update state
    _pcapPacket = 0;
    _state = COPY;
    
    return true;
}

bool
CaptoolPacket::changePayload(const u_char *payload, u_int payloadLength)
{
    assert(payload != 0);
    assert(payloadLength != 0);
    
    // if not in COPY state, make the packet a COPY, not copying the old payload
    if (! makeCopy(false))
        return false;

    // update the packet length to the new length
    // (makeCopy updated length values when removing payload)
    _pcapHeader->caplen += payloadLength;
    _pcapHeader->len = _pcapHeader->caplen;

    
    // update protocols' length and invalidate protocols
    // invalidate protocols
    for (u_int i=0; i<_protocolsNumber; ++i)
    {
        _protocols[i]._payloadLength += payloadLength - _payload._length;
        _protocols[i]._valid = false;
    }
    
    // copy payload
    if (_copyPacket.copy(payload, _protocolsLength, payloadLength)) {
        _payload.reset(0, (u_char *)_copyPacket.get(0) + _protocolsLength, payloadLength, 0, true);
        return true;
    } else
        return false;
}

const u_char *
CaptoolPacket::toByteArray(Module *baseModule, u_int snapLength, bool fixHeaders, pcap_pkthdr const **header)
{
    assert(baseModule != 0);
    assert(header != 0);
    
    // fix headers downwards, until baseModule is reached
    if (fixHeaders) {
        for (u_int i=0; i<_protocolsNumber; ++i)
        {
            if (!_protocols[i]._valid)
            {
                _protocols[i]._module->fixHeader(this);
                _protocols[i]._valid = true;
            }

            if (_protocols[i]._module == baseModule)
            {
                break;
            }
        }
    }
    
    if (baseModule == 0)
    {
        if (snapLength == 0)
        {
            //return original header
            *header = _pcapHeader;
        }
        else
        {
            // return a fake header that contains snapLength as caplen
            _byteArrayHeader.ts = _pcapHeader->ts;
            _byteArrayHeader.len = _pcapHeader->len;
            _byteArrayHeader.caplen = snapLength;
            *header = &_byteArrayHeader;
        }
        return (_state == PCAP) ? _pcapPacket : (u_char *)(_copyPacket.get(0));
    }
    else
    {
                
        /* count packet length from basemodule */
        u_char *ptr = (u_char*)getSegment(baseModule, 0);

        _byteArrayHeader = *_pcapHeader;
        
        // substract protocol lengths 
        for (u_int i=0; i<_protocolsNumber; ++i)
        {
            if (_protocols[i]._module == baseModule)
            {
                break;
            }
            _byteArrayHeader.caplen -= _protocols[i]._length;
            _byteArrayHeader.len -= _protocols[i]._length;
        }
                
        if (snapLength > 0 && (snapLength < _byteArrayHeader.caplen) )
        {
            _byteArrayHeader.caplen = snapLength;
        }
                
        *header = &_byteArrayHeader;
        return ptr;
    }
}

std::string
CaptoolPacket::describe() const
{
    std::stringstream s;
    s << "\n";
    s << "--------------------------------------------------\n";
    s << "CaptoolPacket (state: " << _state << ")";
    s << " len: " << _pcapHeader->len << " caplen: " << _pcapHeader->caplen;
    s << " time: " << _pcapHeader->ts.tv_sec << "." << _pcapHeader->ts.tv_usec;
    s << " no: " << _packetNumber << "\n";

    s << "flowID: " << _flowID << "\n";
    s << "userID: ";
    if (! _userID)
        s << "na";
    else
        s << _userID;
    s << "\n\n";
    
    for (u_int i=0; i<_protocolsNumber; ++i)
    {
        s << "\t" << *_protocols[i]._module->getName() << " (" << _protocols[i]._length << ")"
            << " \t";
        _protocols[i]._module->describe(this, &s);
        s << "\n";
    }
   
    s << "\t" << "payload (" << _payload._length << ")" << "\n";
    s << "--------------------------------------------------" << "\n\n";
    
    return s.str();    
}


} // namespace captool
