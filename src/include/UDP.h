#pragma once

#include "udp.h"
#include "BaseIO.h"

class CUDP : public CBaseIO
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
    CUDP()
    {
    }

    CUDP(const CUDP&);
    CUDP & operator= (const CUDP&);
};
