#pragma once

#include "Neighbor.h"
#include "packet.h"
#include "ip.h"
#include <map>
#include <list>
#include "BaseIO.h"

typedef struct frag_list {
    struct in_addr          saddr,      // fragment source ip address
                            daddr;      // fragment destinatin ip address
    uint8_t                 proto;      // upper protocol used
    uint16_t                id;         // ip header identifier
    uint32_t                len;        // total length of original datagram
    uint32_t                meat;       // received length
    std::list<packet_t*> fragments;     // fragment lists(Notice: the pointed block must be deleted correctly)
} IPFragList;

class CNeighbor;

class CNetwork : public CBaseIO
{
public:
    //
    static CNetwork * instance()
    {
        static CNetwork inst;
        return &inst;
    }

    ~CNetwork();

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
     * Calculate fragment hash code by fragment ip header
     *
     * @iphdr The ip header
     * */
    uint32_t fragmentHashCode(iphdr_t *iphdr);

    /*
     * Do fragmentation
     *
     * @pkt The packet to fragment
     * @mtu The maximum data length of each fragment
     * */
    void fragment(packet_t *pkt, uint16_t mtu);

private:
    /*
     * Return an id and increase it
     *
     * @return An Identifier used by ip header
     * */
    unsigned short getAndIncID(packet_t *pkt);

    /*
     * Reassemble a datagram when all fragments available.
     *
     * @pFrags Fragment list pointer
     * */
    void reasm(IPFragList *pFrags);

    /*
     * Clear fragment cache.
     *
     * @pFrags Target fragment list pointer
     * */
    void clear(IPFragList *pFrags);

    CNetwork() : _neigh(nullptr)
    {
    }

    CNetwork(const CNetwork&);
    CNetwork & operator= (const CNetwork&);

    CNeighbor *_neigh;
    CBaseIO *_tcp;
    CBaseIO *_udp;

    /*key: destination ip address, value: id for ip header*/
    std::map<in_addr_t, unsigned short> _idMap;

    /*key: fragment hash code, value: list for datagram fragments*/
    std::map<uint32_t, IPFragList> _fragsMap;

};

