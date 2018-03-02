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

    /*
     * Send pkt out.
     *
     * @pkt The packet to send
     * */
    void send(packet_t *pkt);

    /*
     * Receive a packet pkt.
     *
     * @pkt The packet received
     * */
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
