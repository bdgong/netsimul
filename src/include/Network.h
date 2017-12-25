#pragma once

#include "Neighbor.h"
#include "UDP.h"
#include "packet.h"
#include "ip.h"

class CNeighbor;

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
     * @pkt The packet to deliver.
     * */
    void deliver(packet_t *pkt);

    /*
     * Received a packet from L2
     *
     * @pkt The received packet
     * */
    void received(packet_t *pkt);

    /*
     * Do defragmentation
     *
     * @iphdr The ip header
     * @pkt The packet to defragment
     * */
    void defragment(iphdr_t *iphdr, packet_t *pkt);

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

