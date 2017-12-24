#pragma once

#include "packet.h"
#include "Neighbor.h"

class CNetwork
{
public:
    //
    static CNetwork * instance()
    {
        static CNetwork inst;
        return &inst;
    }

    void init();

    /*
     * Transport a packet
     *
     * @pkt The packet to send out from local.
     * */
    void send(packet_t *pkt);

    /*
     * Forward a packet
     * */
    void forward(packet_t *pkt);

    /*
     * Deliver received packet to right protocol handler.
     *
     * @pkt The received packet.
     * */
    void deliver(packet_t *pkt);

private:
    //
    bool _isInited;

    CNeighbor *_neigh;

    CNetwork() : 
        _isInited(false),
        _neigh(nullptr)
    {
    }

    CNetwork(const CNetwork&);
    CNetwork & operator= (const CNetwork&);
};

