#include "TCP.h"
#include "Util.h"
#include "CheckSum.h"

#include "udp.h"
#include "ip.h"
#include "ether.h"

#include <algorithm>

#define TAG "<CTCP> "

using std::string;
using std::set;
using std::map;

const uint32_t cMaxHeaderLen = SIZE_ETHERNET + SIZE_IP + SIZE_TCP;

uint16_t cksum_tcp(const tcphdr_t *const tcp, const packet_t *const packet)
{

    uint16_t sum;
    u_char *buf;
    size_t size;
    size_t dataLen;
    pseudo_udp_t pseudo_udp;

    dataLen = (packet->allocated ? packet->len : packet->size); 

    pseudo_udp.saddr    = packet->saddr;
    pseudo_udp.daddr    = packet->daddr;
    pseudo_udp.zero     = 0;
    pseudo_udp.protocol = IPPROTO_TCP;
    pseudo_udp.len      = htons(SIZE_TCP + dataLen);

    size = SIZE_PSEUDO_UDP + SIZE_TCP + packet->size;
    buf = (u_char *)malloc(size);
    memcpy(buf, &pseudo_udp, SIZE_PSEUDO_UDP);
    memcpy(buf + SIZE_PSEUDO_UDP, tcp, SIZE_TCP);
    memcpy(buf + SIZE_PSEUDO_UDP + SIZE_TCP, (packet->allocated ? packet->data : packet->buf), dataLen);

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
    _network->init();

    _isInited = true;
    debug(DBG_DEFAULT, TAG "inited.");
}

CTCP::~CTCP()
{
    log(TAG "desconstructed.\n");
}

int CTCP::send(packet_t *packet)
{
    log(TAG "%s().\n", __func__);
    string key = keyOf(packet->saddr, packet->sport, packet->daddr, packet->dport);
    ConnMap::iterator it = _connPool.find(key);

    if (it == _connPool.end()) {
        error (TAG "%s(): no connection %s found.\n", __func__, key.c_str());
        return 0;
    }

    // put to queue and return

    // get connection send queue
    InetConnSock & sk = it->second;
    PacketQueue & sendQueue = sk.sendQueue;

    u_char *pBuf = packet->buf;
    int dataLeft = packet->size;

    int nextSeq = sk.sendWin.lastSeq + 1,
        endSeq;

    while (dataLeft > 0) {
        // split it
        int dataLen = dataLeft;

        if (sendQueue.empty()) {
            // should allocate a new packet_t
            if (dataLen > cTCPMSS) {
                dataLen = cTCPMSS;
            }
            dataLeft -= dataLen;

            // always allocate fixed size, if there is space left, filled by next time
            std::shared_ptr<packet_t> ppkt(new packet_t(cTCPMSS));
            ppkt->copyMetadata(*packet);
            ppkt->put(dataLen);
            memcpy(ppkt->data, pBuf, dataLen);
            pBuf += dataLen;

            TCP_PKT_CB(ppkt)->seq = nextSeq;
            endSeq = nextSeq + dataLen - 1;
            TCP_PKT_CB(ppkt)->endSeq = endSeq;
            nextSeq = endSeq + 1;

            sendQueue.emplace_back(ppkt);
        }
        else {
            log(TAG "%s(): none empty send queue not handled yet!.\n", __func__);
            std::shared_ptr<packet_t> &tail = sendQueue.back();
            if (tail->len == tail->size) {
                // should allocate a new packet_t
            }
            else if (tail->size < cTCPMSS) {
                // can copy some data here
            }
            else {
                // should not happen
            }
        }

    }

    doSend(&sk);

    // actually, the copied bytes number should be returned
    return packet->size;

}

void CTCP::doSend(InetConnSock *ics)
{
    log(TAG "%s().\n", __func__);
    PacketQueue & sendQueue = ics->sendQueue; 

    int nextSeq = ics->sendWin.lastSeq + 1;
    PacketQueue::iterator it = std::find_if(sendQueue.begin(), sendQueue.end(), [=](const PacketQueue::value_type &ppkt){
        return TCP_PKT_CB(ppkt)->seq == nextSeq;
    });

    if (it == sendQueue.end()) {
        log(TAG "%s(): no match sequence packet found.\n", __func__);
        return ;
    }

    // should check send & receive window first 

    std::shared_ptr<packet_t> &ppkt = *it;

    packet_t pkt(ppkt->len + cMaxHeaderLen); 
    pkt.copyMetadata(*ppkt);

    __doSend(&pkt, ics, TH_SYN, ppkt->buf, ppkt->len);

}

void CTCP::__doSend(packet_t *packet, InetConnSock *ics, uint8_t flags, uint8_t *buf, uint32_t size)
{
    packet->reserve(cMaxHeaderLen);

    // copy payload
    packet->put(size);
    memcpy(packet->data, buf, size); 

    int nextSeq = ics->sendWin.lastSeq + 1;
    int replyAck = ics->sendWin.lastAck;

    tcphdr_t tcphdr;
    tcphdr.th_sport = ics->ics_port;
    tcphdr.th_dport = ics->ics_peerPort;
    tcphdr.th_seq = htonl(nextSeq); 
    tcphdr.th_ack = htonl(replyAck);
    tcphdr.th_offx2 = 0x50;
    tcphdr.th_flags = flags;
    tcphdr.th_win = htons(ics->recvWin.size);
    tcphdr.th_sum = 0;
    tcphdr.th_urp = 0;

    tcphdr.th_sum = cksum_tcp(&tcphdr, packet);

    packet->push(SIZE_TCP);
    memcpy(packet->data, &tcphdr, sizeof(tcphdr));

    _network->send(packet);

}

void CTCP::sendNoData(packet_t *packet, InetConnSock *ics, uint8_t flags)
{
    packet->saddr = ics->ics_addr;
    packet->sport = ics->ics_port;
    packet->daddr = ics->ics_peerAddr;
    packet->dport = ics->ics_peerPort;

    packet->proto = IPPROTO_TCP; 
    packet->reserve(cMaxHeaderLen); 

    tcphdr_t thdr;
    thdr.th_sport = ics->ics_port;
    thdr.th_dport = ics->ics_peerPort;
    thdr.th_seq = htonl(ics->sendWin.lastSeq);
    thdr.th_ack = htonl(ics->sendWin.lastAck);
    thdr.th_offx2 = 0x50;
    thdr.th_flags = flags;
    thdr.th_win = ics->recvWin.size;
    thdr.th_sum = 0;
    thdr.th_urp = 0;

    packet_t emptyPkt;
    emptyPkt.copyMetadata(*packet);
    thdr.th_sum = cksum_tcp(&thdr, &emptyPkt);

    packet->push(SIZE_TCP);
    memcpy(packet->data, &thdr, sizeof(tcphdr_t));

    _network->send(packet);

}

int CTCP::received(packet_t *pkt)
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
        // check current connection state 
        InetConnSock *conn = &it->second;
        if (conn->ics_state == ESTABLISHED) {
            recvEstablished(conn, pkt, tcphdr);
        }
        else {
            recvStateProcess(conn, pkt, tcphdr);
        }
    }
    else {
        // try listening socket
        InetSockMap::iterator iter = _listenPool.find(pkt->dport);
        if (iter != _listenPool.end() && iter->second->sk_state == LISTEN) {
            log(TAG "find listen socket.\n");
            recvListen(iter->second, pkt, tcphdr);
        }
        else {
            log(TAG "no connection or listen socket found, should send RST\n");
            // todo: reply RST
        }
    }

    return 0;

}

void CTCP::recvEstablished(InetConnSock *ics, packet_t *packet, tcphdr_t *tcphdr)
{
}

void CTCP::recvStateProcess(InetConnSock *ics, packet_t *packet, tcphdr_t *tcphdr)
{
    int seq = ntohl(tcphdr->th_seq);
    int ack = ntohl(tcphdr->th_ack);

    switch (tcphdr->th_flags) {
        default:
            log(TAG "%s(): unknown flag: %d.\n", __func__, tcphdr->th_flags);
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
                if (ics->ics_state == SYN_SENT) {
                    // todo: send ACK, connect() finish 
                    int nextSeq = ack;
                    int replyAck = seq + 1;
                    ics->sendWin.lastSeq = nextSeq;
                    ics->sendWin.lastAck = replyAck;

                    packet_t pack(cMaxHeaderLen);
                    sendNoData(&pack, ics, TH_ACK);

                    // we established a connection at client side
                    ics->ics_state = ESTABLISHED;
                    _protoSock->connectFinished(keyOf(ics), ics); 
                }
                else {
                    // what's this?
                    log(TAG "%s(): get SYN and ACK but connection state is not SYN_SENT, just ignore...\n", __func__); 
                }
                break;
            }
        case TH_RST:
        case TH_ACK | TH_RST:
            {
                log(TAG "%s(): RST(or ACK|RST).\n", __func__);
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
                if (ics->ics_state == SYN_RCVD) {
                    // we established a connection at server side
                    ics->ics_state = ESTABLISHED;
                    _protoSock->accept(keyOf(ics), ics);
                }
                else if (ics->ics_state == ESTABLISHED){
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

void CTCP::recvListen(InetSock *sock, packet_t *packet, tcphdr_t *tcphdr)
{
    int seq = ntohl(tcphdr->th_seq);

    // the listen socket only recognize SYN
    if (tcphdr->th_flags == TH_SYN) {
        // create a new socket and let:
        //
        // sk_state = SYN_RCVD
        // CTL = SYN, ACK
        log(TAG "%s(): listened SYN.\n", __func__);
        InetConnSock ics;
        ics._inetSock = *sock;

        ics.ics_peerAddr = packet->saddr;
        ics.ics_peerPort = packet->sport;
        ics.ics_state = SYN_RCVD;

        InetConnSock *conn = newConnection(&ics);

        // send CTL, Wed 14 Mar 2018 18:38:51 
        int replySeq = 1;
        int replyAck = seq + 1;
        conn->sendWin.lastAck = replyAck;
        conn->sendWin.lastSeq = replySeq;

        packet_t pack(cMaxHeaderLen);
        sendNoData(&pack, conn, TH_SYN | TH_ACK);
        log(TAG "%s(): reply ACK|SYN\n" ,__func__);
    }
    else {
        log(TAG "listen socket received flags not SYN.\n");
        // todo: reply RST
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
    int win = 0xffff;

    tcphdr_t tcphdr;
    tcphdr.th_sport = sk->sk_port;
    tcphdr.th_dport = sk->sk_peerPort;
    tcphdr.th_seq = htonl(seq); 
    tcphdr.th_ack = 0;
    tcphdr.th_offx2 = 0x50;
    tcphdr.th_flags = TH_SYN;
    tcphdr.th_win = htons(win);
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
    ics.sendWin.lastAck = 0;
    ics.sendWin.lastSeq = seq;
    ics.sendWin.size = win >> 1;
    ics.recvWin.size = win;

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
    string key = string(inet_ntoa(localAddr)) + "." + std::to_string(ntohs(localPort)) + ","
        + string(inet_ntoa(peerAddr)) + "." + std::to_string(ntohs(peerPort));
    log(TAG "%s(): %s.\n", __func__, key.c_str());
    return key;
}

InetConnSock * CTCP::newConnection(InetConnSock *ics)
{
    ics->ics_sockfd = 0;            // 0 for unaccepted connection

    string key = keyOf(ics);
    auto pair = _connPool.emplace(key, *ics);// std::pair<map<string,InetConnSock>::iterator,bool>
    if (pair.second == true) {
        log (TAG "%s(): created new connection.\n", __func__);
    }

    return &pair.first->second;

}

void CTCP::listen(InetSock *sk) 
{
    _listenPool.emplace(sk->sk_port, sk);
}

