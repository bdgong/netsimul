#include "TCP.h"
#include "Network.h"
#include "Util.h"

#include "ip.h"
#include "ether.h"

#define TAG "<CTCP> "

void CTCP::init()
{
    if (_isInited)
        return;

    CNetwork::instance()->init();
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
    pkt.put(SIZE_TCP);
    memcpy(pkt.data, &tcphdr, sizeof(tcphdr));

    sk->sk_state = SYN_SENT; 
}

