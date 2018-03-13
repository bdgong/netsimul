#include "TCP.h"
#include "Util.h"
#include "CheckSum.h"

#include "udp.h"
#include "ip.h"
#include "ether.h"

#define TAG "<CTCP> "

uint16_t cksum_tcp(const tcphdr_t *const tcp, const packet_t *const packet)
{

    uint16_t sum;
    u_char *buf;
    size_t size;

    pseudo_udp_t pseudo_udp;

    pseudo_udp.saddr    = packet->saddr;
    pseudo_udp.daddr    = packet->daddr;
    pseudo_udp.zero     = 0;
    pseudo_udp.protocol = IPPROTO_TCP;
    pseudo_udp.len      = htons(SIZE_TCP + packet->size);

    size = SIZE_PSEUDO_UDP + SIZE_TCP + packet->size;
    buf = (u_char *)malloc(size);
    memcpy(buf, &pseudo_udp, SIZE_PSEUDO_UDP);
    memcpy(buf + SIZE_PSEUDO_UDP, tcp, SIZE_TCP);
    memcpy(buf + SIZE_PSEUDO_UDP + SIZE_TCP, packet->buf, packet->size);

    sum = cksum(buf, size);

    free(buf);

    return sum;

}

void CTCP::init()
{
    if (_isInited)
        return;

    _network = CNetwork::instance();
    _network->init();
    _isInited = true;
    debug(DBG_DEFAULT, " inited.");
}

CTCP::~CTCP()
{
    log(TAG "desconstructed.\n");
}

void CTCP::connect(InetSock *sk)
{
    log(TAG "%s()\n", __func__);

    // send SYN
    int sizeHdr = SIZE_TCP + SIZE_IP + SIZE_ETHERNET;
    packet_t pkt(sizeHdr);
    pkt.saddr = sk->sk_addr;
    pkt.sport = sk->sk_port;
    pkt.daddr = sk->sk_peerAddr;
    pkt.dport = sk->sk_peerPort;

    pkt.proto = IPPROTO_TCP; 
    pkt.reserve(sizeHdr); 

    tcphdr_t tcphdr;
    tcphdr.th_sport = sk->sk_port;
    tcphdr.th_dport = sk->sk_peerPort;
    tcphdr.th_seq = 2018; 
    tcphdr.th_ack = 0;
    tcphdr.th_offx2 = 0x50;
    tcphdr.th_flags = TH_SYN;
    tcphdr.th_win = 0xffff;
    tcphdr.th_sum = 0;
    tcphdr.th_urp = 0;

    packet_t emptyPkt;
    emptyPkt.copyMetadata(pkt);
    tcphdr.th_sum = cksum_tcp(&tcphdr, &emptyPkt);

    pkt.push(SIZE_TCP);
    memcpy(pkt.data, &tcphdr, sizeof(tcphdr));

    sk->sk_state = SYN_SENT; 

    _network->send(&pkt);

}

