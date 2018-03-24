#include "ProtoSocket.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>

#include <algorithm>

#include "UDP.h"
#include "TCP.h"
#include "Network.h"
#include "Link.h"
#include "Hardware.h"
#include "Util.h"

#define TAG "<CProtoSocket> "

using std::string;

int sig;            // signal received

void handler0(int signo)
{
    sig = signo;
    printf("Received signal INT.\n");
}

void handler1(int signo) 
{
    sig = signo;
    printf("Received signal USR1.\n");
}

void handler2(int signo) 
{
    sig = signo;
    printf("Received signal USR2.\n");
}

CProtoSocket::CProtoSocket()
{
    log(TAG "%s(): sizeof(SockPktType)=%d.\n", __func__, sizeof(SockPktType));
    createSharedMem();
}

CProtoSocket::~CProtoSocket()
{
    destroySharedMem();
    printf("CProtoSocket destructed.\n");
}

void CProtoSocket::createSharedMem()
{
    key_t key;

    if ((key = ftok(cKeyPath, cKeyID)) == -1) {
        fprintf(stderr, "Failed ftok().\n");
    }

    if ((_shmid = shmget(key, cSHMSize, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR |
                    S_IRGRP | S_IWGRP |
                    S_IROTH | S_IWOTH)) == -1) {
        fprintf(stderr, "Failed shmget().\n");
        exit(EXIT_FAILURE);
    }
    else {
        printf("Created shared memory %d.\n", _shmid);
    }

    if ((_pBlock = (SharedBlock *)shmat(_shmid, 0, 0)) == (void *)-1) {
        fprintf(stderr, "Failed shmat().\n");
    }
    else {
        printf("pBlock: %p, pBlock->buf1: %p, pBlock->buf2: %p\n",
                _pBlock, _pBlock->buf1, _pBlock->buf2);
    }
}

void CProtoSocket::destroySharedMem()
{
    if (shmdt(_pBlock) == -1) {
        fprintf(stderr, "Failed shmdt().\n");
    }

    if (shmctl(_shmid, IPC_RMID, 0) == -1) {
        fprintf(stderr, "Failed shmctl().\n");
    }
}

void CProtoSocket::run()
{
    // protocols init, must in order : top-to-down
    CTCP::instance()->init();
    CUDP::instance()->init();
    CNetwork::instance()->init();
    CLink::instance()->init();
    CHardware::instance()->init();

    // catch signals
    signal(SIGUSR1, handler1);
    signal(SIGUSR2, handler2);
    signal(SIGINT, handler0);

    printf("Protocol socket running...\n");

    while (true) {
        pause();

        if (sig == SIGUSR1 || sig == SIGUSR2) {
            handleSockRequest();
            // SIGUSR1 do command work,
            // SIGUSR2 do data work
        }
        else if (sig == SIGINT){
            break;
        }
        else {
            printf("Unknown signal: %d.\n", sig);
        }

        sig = 0;
        printf("Protocols alive...\n");
    }

    printf("Protocol socket exit...\n");
}

void CProtoSocket::handleSockRequest()
{
    SockPacket *sockPkt;

    sockPkt = (SockPacket *)_pBlock->buf2;
    switch (sockPkt->type) {
        case SOCK_CREATE: 
            {
                handleCreate(sockPkt); break;
            }
        case SOCK_BIND:
            {
                handleBind(sockPkt); break;
            }
        case SOCK_SENDTO:
            {
                handleSendTo(sockPkt); break;
            }
        case SOCK_SEND:
            {
                handleSend(sockPkt); break;
            }
        case SOCK_RECVFROM:
            {
                handleRecvFrom(sockPkt); break;
            }
        case SOCK_RECV:
            {
                handleRecv(sockPkt); break;
            }
        case SOCK_CONNECT:
            {
                handleConnect(sockPkt); break;
            }
        case SOCK_LISTEN:
            {
                handleListen(sockPkt); break;
            }
        case SOCK_ACCEPT:
            {
                handleAccept(sockPkt); break;
            }
        case SOCK_CLOSE:
            {
                handleClose(sockPkt); break;
            }
        default:
            fprintf(stderr, "Unkonwn socket packet type: %d.\n", sockPkt->type);
            break;
    }

}

void CProtoSocket::handleCreate(SockPacket *sockPkt)
{   
    Sock *sock;
    sock = (Sock *)sockPkt->data;

    printf("pid: %d, family: %d, type: %d, protocol: %d\n",
            sock->pid, sock->family, sock->type, sock->protocol);
    sock->state = SS_UNCONNECTED;
    InetSock sk{
        ._sock = *sock,
        .sk_state = CLOSED 
    };
    // save to socket pool
    _sockPool.emplace(sock->sockfd, sk);

    // write back sockfd
    memcpy(_pBlock->buf1, &sock->sockfd, sizeof(int));

    afterHandle(sock->pid, SIGUSR1, __func__);
 
}

void CProtoSocket::handleBind(SockPacket *sockPkt)
{
    Sock *sock = (Sock *)sockPkt->data;
    InetSock &cached = _sockPool.at(sock->sockfd);
    cached.sk_addr = sock->addr;
    cached.sk_port = sock->port;

    int success = 1;
    memcpy(_pBlock->buf1, &success, sizeof(success));

    afterHandle(cached.sk_pid, SIGUSR1, __func__);
    //kill(cached.pid, SIGUSR1);
    //log(TAG "%s : kill signal SIGUSR1 to process %d.\n", __func__, cached.pid);
}

void CProtoSocket::handleSendTo(SockPacket *sockPkt)
{
    SockDataHdr *sockDataHdr;
    sockDataHdr = (SockDataHdr *)sockPkt->data;

    struct sockaddr_in *dstAddr = (struct sockaddr_in *)&sockDataHdr->dstAddr;
    printf("socket: %d want to send %d bytes data to %s:%d.\n",
            sockDataHdr->sockfd, sockDataHdr->len,
            inet_ntoa(dstAddr->sin_addr), ntohs(dstAddr->sin_port));

    // get data to send
    char *pData = sockPkt->data;
    pData += sizeof(SockDataHdr);

    // ---- debug only
    char *buf = (char *)malloc(sockDataHdr->len + 1);
    memcpy(buf, pData, sockDataHdr->len);
    buf[sockDataHdr->len] = '\0';
    printf("Contents to send: %s.\n", buf);
    free(buf);
    // ---- /debug only

    packet_t pkt;
    pkt.buf = (unsigned char*)pData;
    pkt.size = sockDataHdr->len;
    pkt.daddr = dstAddr->sin_addr;
    pkt.dport = dstAddr->sin_port;

    // get this socket
    InetSock & sock = _sockPool.at(sockDataHdr->sockfd);

    // set local address as needed
    setLocalAddr(&sock);

    pkt.saddr = sock.sk_addr;
    pkt.sport = sock.sk_port;

    // call UDP::send()
    CUDP::instance()->send(&pkt);
    // 
    // notice, this code assume data will not overflow the buffer size
    // to handle the overflow situation, modify this code
    
    // notify send bytes
    memcpy(_pBlock->buf1, &sockDataHdr->len, sizeof(int));

    afterHandle(sock.sk_pid, SIGUSR2, __func__);
 
}

void CProtoSocket::handleRecvFrom(SockPacket *sockPkt)
{
    SockDataHdr *dataHdr = (SockDataHdr *)sockPkt->data;

    log(TAG "socket %d wanna recvfrom max %d bytes data.\n", dataHdr->sockfd, dataHdr->len);

    // get this socket
    InetSock& sock = _sockPool.at(dataHdr->sockfd);

    // add pending recvfrom socket
    //_pendingSocks.emplace(dataHdr->sockfd, sock.port);
    _pendingSocks.emplace(&sock);
 
    log(TAG "%s : add penging socket %d:%d.\n", __func__, sock.sk_sockfd, ntohs(sock.sk_port));
}

void CProtoSocket::handleSend(SockPacket *sockPkt)
{
    SockDataHdr *sockDataHdr;
    sockDataHdr = (SockDataHdr *)sockPkt->data;

    struct sockaddr_in *srcAddr = (struct sockaddr_in *)&sockDataHdr->srcAddr;
    struct sockaddr_in *dstAddr = (struct sockaddr_in *)&sockDataHdr->dstAddr;

    string key = CTCP::instance()->keyOf(srcAddr->sin_addr, srcAddr->sin_port, dstAddr->sin_addr, dstAddr->sin_port);

    // find connection first
    log(TAG "%s(): %s\n", __func__, key.c_str()); 

    ConnPMap::iterator it = _connPPool.find(key);
    if (it != _connPPool.end()) {
        // get data to send
        char *pData = sockPkt->data;
        pData += sizeof(SockDataHdr);

        // ---- debug only
        char *buf = (char *)malloc(sockDataHdr->len + 1);
        memcpy(buf, pData, sockDataHdr->len);
        buf[sockDataHdr->len] = '\0';
        log(TAG "%s() contents send: %s.\n", __func__, buf);
        free(buf);
        // ---- /debug only

        packet_t pkt;
        pkt.buf = (unsigned char*)pData;
        pkt.size = sockDataHdr->len;
        pkt.saddr = srcAddr->sin_addr;
        pkt.sport = srcAddr->sin_port;
        pkt.daddr = dstAddr->sin_addr;
        pkt.dport = dstAddr->sin_port;

        CTCP::instance()->send(&pkt);
        // notice, this code assume data will not overflow the buffer size
        // to handle the overflow situation, fix this code
        
        memcpy(_pBlock->buf1, &sockDataHdr->len, sizeof(int));
        afterHandle(it->second->ics_pid, SIGUSR2, __func__);
    }
    else {
        log(TAG "%s(): no connection found, report this error\n", __func__);
    }

}

void CProtoSocket::handleRecv(SockPacket *sockPkt)
{
    SockDataHdr *dataHdr = (SockDataHdr *)sockPkt->data;
    struct sockaddr_in *srcAddr = (struct sockaddr_in *)&dataHdr->srcAddr;
    struct sockaddr_in *dstAddr = (struct sockaddr_in *)&dataHdr->dstAddr;

    string key = CTCP::instance()->keyOf(srcAddr->sin_addr, srcAddr->sin_port, dstAddr->sin_addr, dstAddr->sin_port);

    // find connection first
    log(TAG "%s(): %s\n", __func__, key.c_str()); 

    ConnPMap::iterator it = _connPPool.find(key);

    if (it == _connPPool.end()) {
        log(TAG "%s(): no connection found, report this error\n", __func__);
        return ;
    }

    SockDataHdr sdh = *dataHdr;
    sdh.srcAddr = dataHdr->dstAddr;
    sdh.dstAddr = dataHdr->srcAddr;
    sdh.flag = 0;

    InetConnSock *ics = it->second; 

    if (ics->recvQueue.empty()) {
        sdh.len = -1;
    }
    else {
        char *pData = _pBlock->buf1;
        pData += sizeof(SockDataHdr);
        // todo: copy recvQueue data to buffer
        int goalLen = dataHdr->len;
        int copiedLen = 0;

        PacketQueue & recvQueue = ics->recvQueue;

        while (copiedLen < goalLen) {
            std::shared_ptr<packet_t> &ppkt = recvQueue.front();
            int dataLen = ppkt->len;
            if (dataLen > goalLen - copiedLen) {
                dataLen = goalLen - copiedLen;
            }

            memcpy(pData, ppkt->data, dataLen);
            pData += dataLen;
            copiedLen += dataLen;

            ppkt->pull(dataLen);
            if (ppkt->empty()) {
                recvQueue.pop_front();
                
                if (recvQueue.empty()) 
                    break;
            }
        }
        sdh.len = copiedLen;
    }
    memcpy(_pBlock->buf1, &sdh, sizeof(SockDataHdr));
    afterHandle(ics->ics_pid, SIGUSR2, __func__);

    // todo: notify TCP we received data 
}

void CProtoSocket::handleClose(SockPacket *sockPkt)
{
    Sock *sock = (Sock *)sockPkt->data;
    log(TAG "%s() : close socket %d, port %d\n", __func__, sock->sockfd, ntohs(sock->port));

    if (sock->type == SOCK_STREAM) {
        // need do 4wwh
        string name = CTCP::keyOf(sock->addr, sock->port, sock->peerAddr, sock->peerPort);
        ConnPMap::iterator it = _connPPool.find(name);
        if (it != _connPPool.end()) {
            if (it->second->_inetSock._sock.state == SS_DISCONNECTING) {
                log(TAG "%s(): connection is closing...\n", __func__);
            }
            else {
                it->second->_inetSock._sock.state = SS_DISCONNECTING;
                CTCP::instance()->close(name);
            }
        }
        else {
            log(TAG "%s(): no connection find '%s'\n", __func__, name.c_str());
            afterHandle(0, sock->pid, SIGUSR1, __func__);
        }
    }
    else if (sock->type == SOCK_DGRAM) {
        _sockPool.erase(sock->sockfd);
        afterHandle(1, sock->pid, SIGUSR1, __func__);
    }
    else {
        log (TAG "%s(): unsupport sock type: %d\n", __func__, sock->type);
        afterHandle(0, sock->pid, SIGUSR1, __func__);
    }

}

void CProtoSocket::handleListen(SockPacket *sockPkt)
{
    log(TAG "%s().\n", __func__);
    Sock *sock = (Sock *)sockPkt->data; 
    InetSock &cached = _sockPool.at(sock->sockfd);

    char *pData = sockPkt->data;
    pData += sizeof(Sock);

    int backlog = *(int *)pData;
    cached.backlog = backlog;

    cached.sk_state = LISTEN;
    cached._sock.state = SS_CONNECTING; // optional 

    CTCP::instance()->listen(&cached); 

    afterHandle(1, cached.sk_pid, SIGUSR1, __func__); 

}

void CProtoSocket::handleConnect(SockPacket *sockPkt)
{
    Sock *sock = (Sock *)sockPkt->data;

    InetSock &cached = _sockPool.at(sock->sockfd);
    cached.sk_peerAddr = sock->peerAddr;
    cached.sk_peerPort = sock->peerPort;

    // set local address as needed
    setLocalAddr(&cached);

    int result = cached._sock.state;

    if (result == SS_UNCONNECTED) {
        cached._sock.state = SS_CONNECTING;
        CTCP::instance()->connect(&cached);
        // if connect successfully, connectFinished() is called
    }
    else {
        log(TAG "Not unconnected socket: %d.\n", result);
        memcpy(_pBlock->buf1, &result, sizeof(result));
        afterHandle(cached.sk_pid, SIGUSR1, __func__);
    }

}

void CProtoSocket::handleAccept(SockPacket *sockPkt)
{
    log(TAG "%s().\n", __func__);
    Sock *sock = (Sock *)sockPkt->data;
    // when there is a connected connection, return it, otherwise, record an accept request 
    //
    // find a connection without sockfd assigned
    //
    ConnPMap::iterator it = std::find_if(_connPPool.begin(), _connPPool.end(), [=](const ConnPMap::value_type &pair){
                InetConnSock *conn = pair.second;
                return conn->ics_sockfd == 0 && conn->ics_port == sock->port; 
            });

    if (it != _connPPool.end()) {
        // find a connection, return it
        InetConnSock *ics = it->second;
        ics->ics_sockfd = selectFD();

        Sock *newSock = (Sock *)ics;
        memcpy(_pBlock->buf1, newSock, sizeof(Sock));
        afterHandle(newSock->pid, SIGUSR1, __func__);
    }
    else {
        // no available connection yet
        _pendingAccept.insert(sock->port);
    }

}

void CProtoSocket::connectFinished(string name, InetConnSock *ics)
{
    log(TAG "%s(): %s.\n", __func__, name.c_str());
    ics->_inetSock._sock.state = SS_CONNECTED;
    _connPPool.emplace(name, ics); 

    // here, no notify the connected address, a data structure must be returned instead of
    // a single flag show failed or success
    memcpy(_pBlock->buf1, ics, sizeof(Sock));

    afterHandle(ics->ics_pid, SIGUSR1, __func__);
}

void CProtoSocket::accepted(std::string name, InetConnSock *ics)
{
    log(TAG "%s(): %s.\n", __func__, name.c_str());
    ics->_inetSock._sock.state = SS_CONNECTED;
    auto pair = _connPPool.emplace(name, ics);

    std::set<uint16_t>::iterator it = _pendingAccept.find(ics->ics_port);
    if (it != _pendingAccept.end()) {
        ics->ics_sockfd = selectFD(); 
        memcpy(_pBlock->buf1, ics, sizeof(Sock));

        _pendingAccept.erase(ics->ics_port);

        afterHandle(ics->ics_pid, SIGUSR1, __func__);
    }
    else {
        log (TAG "%s(): no accept request at port %d\n", __func__, ics->ics_port);
    }
}

void CProtoSocket::closed(std::string name)
{
    log(TAG "%s(): %s\n", __func__, name.c_str());
    // remove connection
    ConnPMap::iterator it = _connPPool.find(name);
    int result;
    uint32_t pid = it->second->ics_pid;
    if (it != _connPPool.end()) {
        _connPPool.erase(it);
        log(TAG "%s(): now there is %d connection\n", __func__, _connPPool.size());
        result = 1;
    }
    else {
        result = 0;
        log(TAG "%s(): connection not found\n", __func__);
    }

    log(TAG "%s(): now there is %d socket\n", __func__, _sockPool.size());

    afterHandle(result, pid, SIGUSR1, __func__);
}

uint16_t CProtoSocket::selectPort()
{
    return 1314;
}

uint32_t CProtoSocket::selectFD()
{
    return 15110;
}


void CProtoSocket::setLocalAddr(InetSock * sock)
{
    // get source ip address if not bind yet, 
    // if has bound, port will not be 0
    if (sock->sk_port == 0) {           // not bind yet
        const Device *dev = CHardware::instance()->getDefaultDevice();
        sock->sk_addr = dev->ipAddr;
        sock->sk_port = htons(selectPort());
    } else {}

}

void CProtoSocket::bytesAvailable(InetConnSock *ics)
{
    log (TAG "%s()\n", __func__);
}

void CProtoSocket::received(const packet_t *pkt)
{
    log (TAG "Received %d bytes data.\n", pkt->len);
    log (TAG "_pendSocks: \n");
    for_each (_pendingSocks.cbegin(), _pendingSocks.cend(), [=](const InetSock *sock){
        log("pid: %d, sockfd: %d, port: %d\n", sock->sk_pid, sock->sk_sockfd, ntohs(sock->sk_port));
    });
    // find pending socket
    auto p = std::find_if(_pendingSocks.cbegin(), _pendingSocks.cend(),
                [=](const InetSock* sock){
                    return (sock->sk_port == pkt->dport);
                });
    if (p != _pendingSocks.cend()) {
        const InetSock* sock = *p;

        // todo: copy pkt data to shared memory
        SockDataHdr dataHdr;
        dataHdr.sockfd  = sock->sk_sockfd;
        dataHdr.len     = pkt->len;

        struct sockaddr_in srcAddr;
        srcAddr.sin_addr = pkt->saddr;
        srcAddr.sin_port = pkt->sport;
        srcAddr.sin_family = AF_INET;

        struct sockaddr_in dstAddr;
        dstAddr.sin_addr = pkt->daddr;
        dstAddr.sin_port = pkt->dport;
        dstAddr.sin_family = AF_INET;

        dataHdr.srcAddr = srcAddr;
        dataHdr.dstAddr = dstAddr;

        dataHdr.flag    = 0;

        char *pData = _pBlock->buf1;
        memcpy(pData, &dataHdr, sizeof(dataHdr));
        pData += sizeof(dataHdr);

        memcpy(pData, pkt->data, pkt->len);
        pData += pkt->len;

        _pendingSocks.erase(p);

        afterHandle(sock->sk_pid, SIGUSR2, __func__);
    }
    else {
        log(TAG "No pending socket port %d find.\n", ntohs(pkt->dport));
    }

}

void CProtoSocket::afterHandle(int success, int pid, int signo, const char * const funcName)
{
    memcpy(_pBlock->buf1, &success, sizeof(success));
    afterHandle(pid, signo, funcName);
}

void CProtoSocket::afterHandle(int pid, int signo, const char *funcName)
{
    usleep(100);            // VIP: wait CSocket enter pause() statement
    kill(pid, signo);
    //log(TAG "%s() : kill signal %d to process %d.\n", funcName, signo, pid);
}

