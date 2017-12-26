#include "Network.h"

#include "ip.h"
#include "CheckSum.h"
#include "Util.h"

#include <cstring>

const tok_t ipproto_values[] = {
    {IPPROTO_TCP, "TCP"},
    {IPPROTO_UDP, "UDP"},
    {IPPROTO_ICMP, "ICMP"},
    {IPPROTO_IP, "IP"},
    {0, NULL}
};

/*
 * A simple implementation of `ip_select_fb_ident()`
 * */
uint16_t CNetwork::getAndIncID(packet_t *pkt)
{
    in_addr_t daddr = pkt->daddr.s_addr;

    uint16_t id;
    if (_idMap.count(daddr) == 1) {
        // find it
        id = _idMap.at(daddr) + 1;
    }
    else {
        // not found, create one
        srand((unsigned int)time(NULL));
        id = rand() % 0xFFFF;
    }
    _idMap[daddr] = id;         // update cache
    return id;

}

void CNetwork::send(packet_t *pkt)
{
    if (pkt->len > 0xFFFF) {
        debug(DBG_DEFAULT, "Too big packet to send.");
        return ;
    }

    pkt->ept     = ETH_P_IP;

    const Device *dev = CLink::instance()->getDefaultDevice();
    uint16_t mtu = dev->mtu;

    if (SIZE_IP + pkt->len > mtu) {
        fragment(pkt, mtu);
    }
    else {
        // prepare IP header
        iphdr_t ip;
        size_t size_new = SIZE_IP + pkt->len; 

        ip.ip_vhl   = 0x45;
        ip.ip_tos   = 0;
        ip.ip_len   = htons(size_new);
        ip.ip_id    = htons(getAndIncID(pkt));
        ip.ip_off   = htons(IP_DF);     // don't fragment
        ip.ip_ttl   = IPDEFTTL;         // default TTL
        ip.ip_p     = pkt->proto;
        ip.ip_sum   = 0;
        ip.ip_src   = pkt->saddr;
        ip.ip_dst   = pkt->daddr;

        ip.ip_sum   = cksum((u_char *)&ip, SIZE_IP);

        // push IP header space
        pkt->push(SIZE_IP);
        // copy IP header
        memcpy(pkt->data, &ip, SIZE_IP);

        _neigh->send(pkt);
    }

}

void CNetwork::fragment(packet_t *pkt, uint16_t mtu)
{
    debug(DBG_DEFAULT, "<Network> Do fragment.");
    iphdr_t ip;

    ip.ip_vhl   = 0x45;
    ip.ip_tos   = 0;
    //ip.ip_len   = htons(size_new);
    ip.ip_id    = htons(getAndIncID(pkt));
    //ip.ip_off   = htons(IP_DF);    // don't fragment
    ip.ip_ttl   = IPDEFTTL;         // default TTL
    ip.ip_p     = pkt->proto;
    ip.ip_sum   = 0;
    ip.ip_src   = pkt->saddr;
    ip.ip_dst   = pkt->daddr;

    unsigned int left   = pkt->len; // total length
    unsigned int len    = 0;        // current fragment length
    unsigned char *ptr  = pkt->data;// fragment start position
    uint16_t offset     = 0;

    while (left > 0) {
        len = left;

        if (len + SIZE_IP > mtu) {
            len = mtu - SIZE_IP;
        }

        if (len < left) {
            len &= ~7;          // align eight byte 
        }

        left -= len;

        // allocate fragment packet 
        packet_t pkt2(ETH_HLEN + SIZE_IP + len); 
        pkt2.copyMetadata(*pkt);
        pkt2.reserve(ETH_HLEN + SIZE_IP);
        pkt2.put(len);
        memcpy(pkt2.data, ptr, len);

        // set ip header
        iphdr_t iphdr = ip;

        iphdr.ip_len    = htons(SIZE_IP + len);
        iphdr.ip_off    = htons(offset >> 3);

        if (left > 0) {
            iphdr.ip_off |= htons(IP_MF);
        }

        iphdr.ip_sum    = cksum((u_char *)&iphdr, SIZE_IP);

        pkt2.push(SIZE_IP);
        memcpy(pkt2.data, &iphdr, SIZE_IP);

        offset += len;

        debug(DBG_DEFAULT, "<Network> send out fragment: %d bytes.", len);
        _neigh->send(&pkt2);

    } // while

}

void CNetwork::forward(packet_t *pkt)
{
    debug(DBG_DEFAULT, "<Network> forward to be implemented.");
}

void CNetwork::deliver(packet_t *pkt)
{
    pkt->pull(SIZE_IP);

    switch (pkt->proto) {
        case IPPROTO_TCP:
            {
                break;
            }
        case IPPROTO_UDP:
            {
                CUDP::instance()->received(pkt);
                break;
            }
        case IPPROTO_ICMP:
            {
                break;
            }
        case IPPROTO_IP:
            {
                break;
            }
        default:
            break;
    }

}

void CNetwork::defragment(iphdr_t *iphdr, packet_t *pkt)
{
    // assume no fragmentation need
    debug(DBG_DEFAULT, "<Network> defragment.");
    
}

void CNetwork::received(packet_t *pkt)
{
    debug(DBG_DEFAULT, "<Network> received.");
    iphdr_t *iphdr = (iphdr_t *)pkt->data;

    if (IP_HL(iphdr)*4 < 20) {
        error("Invalid ip header.\n");
        return ;
    }

    pkt->saddr = iphdr->ip_src;
    pkt->daddr = iphdr->ip_dst;
    pkt->proto = iphdr->ip_p;

    /* print source and destination IP addresses */
    debug("       From: %s\n", inet_ntoa(pkt->saddr));
    debug("         To: %s\n", inet_ntoa(pkt->daddr));
    debug("   Protocol: %s (%03d)\n",
            tok2str(ipproto_values, "Unknown", pkt->proto), pkt->proto);

    // check for local deliver or forward by compare destination address
    const Device *dev = CLink::instance()->getDefaultDevice();
    if (dev->ipAddr.s_addr != pkt->daddr.s_addr ) {
        forward(pkt);
    }
    else {
        if (iphdr->isFragment()) {
            defragment(iphdr, pkt);
        }
        else {
            deliver(pkt);
        }
    }
    
}

void CNetwork::init()
{
    if (_isInited)
        return;

    _neigh = CNeighbor::instance();
    _neigh->init();

    _isInited = true;
    debug(DBG_DEFAULT, "<Network> inited");

}

