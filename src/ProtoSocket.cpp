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

inline void afterHandle(int pid, int signo, const char *funcName)
{
    usleep(100);            // VIP: wait CSocket enter pause() statement
    kill(pid, signo);
    log(TAG "%s() : kill signal %d to process %d.\n", funcName, signo, pid);
}

CProtoSocket::CProtoSocket()
{
    //init();
    // protocols init
    CHardware::instance()->init();
    CLink::instance()->init();
    CNetwork::instance()->init();
    CUDP::instance()->init();

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
    // boot protocols
    CUDP::instance()->init(); 

    // catch signals
    signal(SIGUSR1, handler1);
    signal(SIGUSR2, handler2);
    signal(SIGINT, handler0);

    printf("Protocol running...\n");

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
        case SockPktCreate: 
            {
                handleCreate(sockPkt); break;
            }
        case SockPktBind:
            {
                handleBind(sockPkt); break;
            }
        case SockPktSendTo:
            {
                handleSendTo(sockPkt); break;
            }
        case SockPktRecvFrom:
            {
                handleRecvFrom(sockPkt); break;
            }
        case SockPktConnect:
            {
                handleConnect(sockPkt); break;
            }
        case SockPktListen:
            {
                handleListen(sockPkt); break;
            }
        case SockPktAccept:
            {
                handleAccept(sockPkt); break;
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
    InetSock sk{
        ._sock = *sock,
        .sk_state = UNCONNECTED
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
    // ---- /debug only

    packet_t pkt;
    pkt.buf = (unsigned char*)buf;
    pkt.size = sockDataHdr->len;
    pkt.daddr = dstAddr->sin_addr;
    pkt.dport = dstAddr->sin_port;

    // get this socket
    InetSock & sock = _sockPool.at(sockDataHdr->sockfd);

    // get source ip address if not bind yet, 
    // if has bound, port will not be 0
    if (sock.sk_port == 0) {           // not bind yet
        const Device *dev = CHardware::instance()->getDefaultDevice();
        sock.sk_addr = dev->ipAddr;
        sock.sk_port = htons(selectPort());
    } else {}

    pkt.saddr = sock.sk_addr;
    pkt.sport = sock.sk_port;

    // call UDP::send()
    CUDP::instance()->send(&pkt);
    // 
    // notice, this code assume data will not overflow the buffer size
    // to handle the overflow situation, modify this code
    
    free(buf);

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

void CProtoSocket::handleClose(SockPacket *sockPkt)
{
    Sock *sock = (Sock *)sockPkt->data;

    _sockPool.erase(sock->sockfd);

    log(TAG "%s() : Close socket %d.\n", __func__, sock->sockfd);
}

void CProtoSocket::handleListen(SockPacket *sockPkt)
{
}

void CProtoSocket::handleConnect(SockPacket *sockPkt)
{
    Sock *sock = (Sock *)sockPkt->data;

    InetSock &cached = _sockPool.at(sock->sockfd);
    cached.sk_peerAddr = sock->peerAddr;
    cached.sk_peerPort = sock->peerPort;

    CTCP::instance()->connect();
}

void CProtoSocket::handleAccept(SockPacket *sockPkt)
{
}

unsigned short CProtoSocket::selectPort()
{
    return 1314;
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

        dataHdr.srcAddr = *((struct sockaddr*)&srcAddr);
        dataHdr.dstAddr = *((struct sockaddr*)&dstAddr);

        dataHdr.flag    = 0;

        char *pData = _pBlock->buf1;
        memcpy(pData, &dataHdr, sizeof(dataHdr));
        pData += sizeof(dataHdr);

        memcpy(pData, pkt->data, pkt->len);
        pData += pkt->len;

        _pendingSocks.erase(p);

        afterHandle(sock->sk_pid, SIGUSR2, __func__);
        //kill(sock->pid, SIGUSR2);
        //log (TAG "%s : kill signal SIGUSR2 to process %d.\n", __func__, sock->pid);
    }
    else {
        // todo: no pending socket find
        log(TAG "No pending socket port %d find.\n", ntohs(pkt->dport));
    }

}

