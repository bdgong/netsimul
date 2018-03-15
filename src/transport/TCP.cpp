#include "TCP.h"
#include "Util.h"
#include "CheckSum.h"

#include "udp.h"
#include "ip.h"
#include "ether.h"

#define TAG "<CTCP> "

using std::string;
using std::set;
using std::map;

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

    _protoSock = CProtoSocket::instance();
    _network = CNetwork::instance();

    _isInited = true;
    debug(DBG_DEFAULT, TAG "inited.");
}

CTCP::~CTCP()
{
    log(TAG "desconstructed.\n");
}

void CTCP::send(packet_t *pkt)
{
}

void CTCP::received(packet_t *pkt)
{
    log(TAG "%s().\n", __func__);

    tcphdr_t *tcphdr = (tcphdr_t *)pkt->data;
    pkt->sport = tcphdr->th_sport;
    pkt->dport = tcphdr->th_dport;

    log(TAG "%s(): pkt->size = %d, pkt->len = %d.\n", __func__, pkt->size, pkt->len);
    int sizeTCPHdr = TH_OFF(tcphdr) * 4;
    pkt->pull(sizeTCPHdr);
    log(TAG "%s(): pkt->size = %d, pkt->len = %d.\n", __func__, pkt->size, pkt->len);

    int seq = ntohl(tcphdr->th_seq);
    int ack = ntohl(tcphdr->th_ack);

    // check existing connection
    string key = keyOf(pkt->daddr, pkt->dport, pkt->saddr, pkt->sport);
    ConnMap::iterator it = _connPool.find(key); 
    if (it != _connPool.end()) {
        // check current connection state and received packet header flag
        InetConnSock *conn = &it->second;

        switch (tcphdr->th_flags) {
            default:
                log(TAG "%s(): unknown flag: %x.\n", __func__, tcphdr->th_flags);
                break;
            case TH_FIN:
                {
                    log(TAG "%s(): FIN.\n", __func__);
                    break;
                }
            case TH_SYN:
                {
                    log(TAG "%s(): SYN.\n", __func__);
                    break;
                }
            case TH_SYN | TH_ACK:
                {
                    log(TAG "%s(): SYN and ACK.\n", __func__); 
                    if (conn->ics_state == SYN_SENT) {
                        // todo: send ACK, connect() finish 
                        int replySeq = ack;
                        int replyAck = seq + 1;

                        int sizeHdr = SIZE_TCP + SIZE_IP + SIZE_ETHERNET;
                        packet_t pack(sizeHdr);
                        pack.saddr = conn->ics_addr;
                        pack.sport = conn->ics_port;
                        pack.daddr = conn->ics_peerAddr;
                        pack.dport = conn->ics_peerPort;

                        pack.proto = IPPROTO_TCP; 
                        pack.reserve(sizeHdr); 

                        tcphdr_t thdr;
                        thdr.th_sport = conn->ics_port;
                        thdr.th_dport = conn->ics_peerPort;
                        thdr.th_seq = htonl(replySeq);
                        thdr.th_ack = htonl(replyAck);
                        thdr.th_offx2 = 0x50;
                        thdr.th_flags = TH_ACK;
                        thdr.th_win = 0xffff;
                        thdr.th_sum = 0;
                        thdr.th_urp = 0;

                        packet_t emptyPkt;
                        emptyPkt.copyMetadata(pack);
                        thdr.th_sum = cksum_tcp(&thdr, &emptyPkt);

                        pack.push(SIZE_TCP);
                        memcpy(pack.data, &thdr, sizeof(tcphdr_t));

                        _network->send(&pack);

                        // we established a connection at client side
                        conn->ics_state = ESTABLISHED;
                        _protoSock->connectFinished(key, conn); 
                    }
                    else {
                        // what's this?
                        log(TAG "%s(): get SYN and ACK but connection state is not SYN_SENT, just ignore...\n", __func__); 
                    }
                    break;
                }
            case TH_RST:
                {
                    log(TAG "%s(): RST.\n", __func__);
                    break;
                }
            case TH_PUSH:
                {
                    log(TAG "%s(): PUSH.\n", __func__);
                    break;
                }
            case TH_ACK:
                {
                    log(TAG "%s(): ACK.\n", __func__);
                    if (conn->ics_state == SYN_RCVD) {
                        // we established a connection at server side
                        conn->ics_state = ESTABLISHED;
                        _protoSock->accept(key, conn);
                    }
                    else if (conn->ics_state == ESTABLISHED){
                        log(TAG "%s(): received a data packet.\n", __func__);
                    }
                    else {
                        log(TAG "%s(): a connection received ACK but state neither SYN_RCVD nor ESTABLISHED.\n", __func__);
                    }
                    break;
                }
            case TH_URG:
                {
                    log(TAG "%s(): URG.\n", __func__);
                    break;
                }
        }
    }
    else {
        // try listening socket
        InetSockMap::iterator iter = _listenPool.find(pkt->dport);
        if (iter != _listenPool.end() && iter->second->sk_state == LISTEN) {
            log(TAG "find listen socket.\n");
            // the listen socket only recognize SYN
            if (tcphdr->th_flags == TH_SYN) {
                // create a new socket and let:
                //
                // sk_state = SYN_RCVD
                // CTL = SYN, ACK
                InetConnSock ics;
                ics._inetSock = *iter->second;

                ics.ics_peerAddr = pkt->saddr;
                ics.ics_peerPort = pkt->sport;

                ics.ics_state = SYN_RCVD;

                InetConnSock *conn = newConnection(&ics);

                // todo: send CTL, Wed 14 Mar 2018 18:38:51 
                int replySeq = 300;
                int replyAck = seq + 1;
                conn->lastAck = replyAck;
                conn->lastSeq = replySeq;

                int sizeHdr = SIZE_TCP + SIZE_IP + SIZE_ETHERNET;
                packet_t pack(sizeHdr);
                pack.saddr = conn->ics_addr;
                pack.sport = conn->ics_port;
                pack.daddr = conn->ics_peerAddr;
                pack.dport = conn->ics_peerPort;

                pack.proto = IPPROTO_TCP; 
                pack.reserve(sizeHdr); 

                tcphdr_t thdr;
                thdr.th_sport = conn->ics_port;
                thdr.th_dport = conn->ics_peerPort;
                thdr.th_seq = htonl(replySeq);
                thdr.th_ack = htonl(replyAck);
                thdr.th_offx2 = 0x50;
                thdr.th_flags = TH_SYN | TH_ACK;
                thdr.th_win = 0xffff;
                thdr.th_sum = 0;
                thdr.th_urp = 0;

                packet_t emptyPkt;
                emptyPkt.copyMetadata(pack);
                thdr.th_sum = cksum_tcp(&thdr, &emptyPkt);

                pack.push(SIZE_TCP);
                memcpy(pack.data, &thdr, sizeof(tcphdr_t));

                _network->send(&pack);       
            }
            else {
                log(TAG "listen socket received flags not SYN.\n");
                // todo: reply RST
            }
        }
        else {
            log(TAG "no connection or listen socket found, should send RST");
            // todo: reply RST
        }
    }

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

    int seq = 2018;

    tcphdr_t tcphdr;
    tcphdr.th_sport = sk->sk_port;
    tcphdr.th_dport = sk->sk_peerPort;
    tcphdr.th_seq = htonl(seq); 
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

    // save to connection pool
    InetConnSock ics;
    ics._inetSock = *sk;
    ics.lastAck = 0;
    ics.lastSeq = seq;
    ics.window = 0xffff;

    string key = keyOf(&ics);
    _connPool.emplace(key, ics);

    _network->send(&pkt);

}

string CTCP::keyOf(InetConnSock *ics)
{
    return keyOf(ics->ics_addr, ics->ics_port, ics->ics_peerAddr, ics->ics_peerPort);
}

string CTCP::keyOf(struct in_addr localAddr, uint16_t localPort,
        struct in_addr peerAddr, uint16_t peerPort)
{
    //return string(std::to_string(localAddr.s_addr) + "." + std::to_string(localPort) + ","
            //+ std::to_string(peerAddr.s_addr) + "." + std::to_string(peerPort));
    string key = string(inet_ntoa(localAddr)) + "." + std::to_string(localPort) + ","
        + string(inet_ntoa(peerAddr)) + "." + std::to_string(peerPort);
    log(TAG "%s(): %s.\n", __func__, key.c_str());
    return key;
}

InetConnSock * CTCP::newConnection(InetConnSock *ics)
{
    ics->ics_sockfd = 0;            // 0 for unaccepted connection

    string key = keyOf(ics);
    auto pair = _connPool.emplace(key, *ics);// std::pair<map<string,InetConnSock>::iterator,bool>
    if (pair.second == true) {
        log (TAG, "%s(): created new connection.\n", __func__);
    }

    return &pair.first->second;

}

void CTCP::listen(InetSock *sk) 
{
    _listenPool.emplace(sk->sk_port, sk);
}

