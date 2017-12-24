#include "Network.h"

#include "ip.h"
#include "CheckSum.h"
#include "Util.h"

#include <cstring>

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
}

void CNetwork::deliver(packet_t *pkt)
{
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

