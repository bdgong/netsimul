#include "UDP.h"
#include "Network.h"
#include "Util.h"
#include "CheckSum.h"
#include "ProtoSocket.h"
#include "ether.h"
#include <string>

#define TAG "<CUDP> "

const unsigned int cMaxBufferSize = 4096;

uint16_t cksum_udp(const udphdr_t *const udp, const packet_t *const packet)
{

    uint16_t sum;
    u_char *buf;
    size_t size;

    pseudo_udp_t pseudo_udp;

    pseudo_udp.saddr    = packet->saddr;
    pseudo_udp.daddr    = packet->daddr;
    pseudo_udp.zero     = 0;
    pseudo_udp.protocol = IPPROTO_UDP;
    pseudo_udp.len      = udp->uh_len;

    size = SIZE_PSEUDO_UDP + SIZE_UDP + packet->size;
    buf = (u_char *)malloc(size);
    memcpy(buf, &pseudo_udp, SIZE_PSEUDO_UDP);
    memcpy(buf+SIZE_PSEUDO_UDP, udp, SIZE_UDP);
    memcpy(buf+SIZE_PSEUDO_UDP+SIZE_UDP, packet->buf, packet->size);

    sum = cksum(buf, size);

    free(buf);

    return sum;

}

void CUDP::init()
{
    if (_isInited)
        return ;

    CNetwork::instance()->init();
    _isInited = true;
    debug(DBG_DEFAULT, "<UDP> inited.");
}

void CUDP::send(packet_t *packet)
{
    log (TAG "%s\n", __func__);
    // make a copy of original data
    int sizeHdr = SIZE_UDP + SIZE_IP + SIZE_ETHERNET;

    // allocate more space include header
    packet_t pkt(sizeHdr + packet->size);
    pkt.copyMetadata(*packet);

    pkt.proto = IPPROTO_UDP;

    // reserve space for header
    pkt.reserve(sizeHdr);

    // copy payload
    pkt.put(packet->size);
    memcpy(pkt.data, packet->buf, packet->size);

    // prepare UDP header
    udphdr_t udp; 
    size_t size_new = SIZE_UDP + packet->size;

    //udp.uh_sport    = htons(packet->sport);
    //udp.uh_dport    = htons(packet->dport);
    udp.uh_sport    = packet->sport;
    udp.uh_dport    = packet->dport;
    udp.uh_len      = htons(size_new);
    udp.uh_sum      = 0;

    udp.uh_sum      = cksum_udp(&udp, packet);

    // push UDP header space
    pkt.push(SIZE_UDP);

    // copy UDP header
    memcpy(pkt.data, &udp, SIZE_UDP);

    log (TAG "%s() : from %d to %d.\n", __func__, ntohs(udp.uh_sport), ntohs(udp.uh_dport));
    // call network to do next work
    CNetwork *network = CNetwork::instance();
    network->send(&pkt);

}

void CUDP::received(packet_t *pkt)
{
    debug(DBG_DEFAULT, "<UDP> received.");
    udphdr_t *udphdr = (udphdr_t *)pkt->data;
    uint16_t dataLen = ntohs( udphdr->uh_len ) - SIZE_UDP;

    pkt->sport  = udphdr->uh_sport;
    pkt->dport  = udphdr->uh_dport;

    pkt->pull(SIZE_UDP);
    //std::string msg((const char*)pkt->data, dataLen);

    //debug(DBG_DEFAULT, "Received data length=%d : \n%s", dataLen, msg.c_str());
    CProtoSocket::instance()->received(pkt);

}

