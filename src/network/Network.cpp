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

void CNetwork::send(packet_t *pkt)
{

    if (pkt->len > 0xFFFF) {
        debug(DBG_DEFAULT, "Too big packet to send.");
        return ;
    }
    
    // prepare IP header
    iphdr_t ip;
    size_t size_new = SIZE_IP + pkt->len; 

    ip.ip_vhl   = 0x45;
    ip.ip_tos   = 0;
    ip.ip_len   = htons(size_new);
    ip.ip_id    = htons(0xF96D);
    ip.ip_off   = htons(IP_DF);     // don't fragment
    ip.ip_ttl   = IPDEFTTL;         // default TTL
    ip.ip_p     = INJECT_OP_TCP(pkt) ? IPPROTO_TCP : IPPROTO_UDP;
    ip.ip_sum   = 0;
    ip.ip_src   = pkt->saddr;
    ip.ip_dst   = pkt->daddr;

    ip.ip_sum   = cksum((u_char *)&ip, SIZE_IP);

    // push IP header space
    pkt->push(SIZE_IP);

    // copy IP header
    memcpy(pkt->data, &ip, SIZE_IP);

    pkt->ept     = ETH_P_IP;

    // assume no fragment needed
    _neigh->send(pkt);

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
    deliver(pkt);
    
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

    // check for local deliver or forward by dest address
    const Device *dev = CLink::instance()->getDefaultDevice();
    if (dev->ipAddr.s_addr != pkt->daddr.s_addr ) {
        forward(pkt);
    }
    else {
        defragment(iphdr, pkt);
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

