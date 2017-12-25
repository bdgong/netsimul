#pragma once

#include "udp.h"
#include "packet.h"

class CUDP
{
public:
    static CUDP * instance()
    {
        static CUDP inst;
        return &inst;
    }
    //
    void init();

    void received(packet_t *pkt);
private:
    //
    bool _isInited;

    CUDP() : _isInited(false)
    {
    }

    CUDP(const CUDP&);
    CUDP & operator= (const CUDP&);
};
