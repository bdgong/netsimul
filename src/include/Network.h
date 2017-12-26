#pragma once

#include "Neighbor.h"
#include "UDP.h"
#include "packet.h"
#include "ip.h"
#include <map>
#include <list>

typedef struct frag_list {
    uint32_t len;                       // the total length of fragments
    std::list<packet_t*> fragments;     // fragment lists(Notice: the pointed block must be deleted correctly)
} IPFragList;

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
     * Add ip header, then transport this packet
     *
     * @pkt The packet to send out from local.
     * */
    void send(packet_t *pkt);

    /*
     * Forward a packet.  The ip header already in the packet.
     *
     * @pkt The packet to be forwarded
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

    /*
     * Do fragmentation
     *
     * @pkt The packet to fragment
     * @mtu The maximum data length of each fragment
     * */
    void fragment(packet_t *pkt, uint16_t mtu);

private:
    //
    bool _isInited;

    CNeighbor *_neigh;

    /*key: destination ip address, value: id for ip header*/
    std::map<in_addr_t, unsigned short> _idMap;

    /*key: fragment hash code, value: list for fragments*/
    std::map<uint32_t, IPFragList> _fragsMap;

    /*
     * Return an id and increase it
     *
     * @return An Identifier used by ip header
     * */
    unsigned short getAndIncID(packet_t *pkt);

    CNetwork() : 
        _isInited(false),
        _neigh(nullptr)
    {
    }

    CNetwork(const CNetwork&);
    CNetwork & operator= (const CNetwork&);
};

