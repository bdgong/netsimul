#pragma once

#include "packet.h"

/*
 * BaseIO - Basic input and output interface
 * */
class CBaseIO
{
    public:
        CBaseIO() : _isInited(false)
        {
        }
        virtual ~CBaseIO()
        {
        }

        virtual void init() = 0;
        virtual void send(packet_t *pkt) = 0;
        virtual void received(packet_t *pkt) = 0;
    protected:
        bool _isInited; 
};

