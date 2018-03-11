#include "Socket.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ipc.h> 
#include <sys/stat.h> 
#include <sys/shm.h> 

#include "Util.h"

#define TAG "<CSocket> "

int sig;            // received signal

void handler1(int signo)
{
    printf("Received signal SIGUSR1(%d).\n", signo);
    sig = signo;
}

void handler2(int signo)
{
    sig = signo;
    printf("Received signal SIGUSR2(%d).\n", signo);
}



CSocket::CSocket()
{
    attachSharedMem();
}

CSocket::~CSocket()
{
    detachSharedMem();

    close();
}

void CSocket::attachSharedMem()
{
    key_t key;          // shared memory key
    struct shmid_ds buf;

    signal(SIGUSR1, handler1);          // SIGUSR1 for commands
    signal(SIGUSR2, handler2);          // SIGUSR2 for datas

    // prepare a key 
    if ((key = ftok(cKeyPath, cKeyID)) == -1) {
        printf("Failed ftok().\n");
    }

    // try attach Protocol process created shared memory
    if ((_shmid = shmget(key, cSHMSize, IPC_CREAT | IPC_EXCL)) == -1) {
        if (errno == EEXIST) {
            if ((_shmid = shmget(key, cSHMSize, IPC_CREAT | S_IRUSR | S_IWUSR)) == -1) {
                printf("Failed shmget(): %s.\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            else {
                printf("Success attach shared memory %d.\n", _shmid);
            }
        }
        else {
            // no shared memory exist, maybe Protocol not started, exit...
            fprintf(stderr, "Unable to attach shared memory.\n");
            exit(0);
        }
    }
    else {
        if (shmctl(_shmid, IPC_RMID, 0) == -1) {
            printf("Failed shmctl(): %s.\n", strerror(errno));
        }
        printf("Protocol not started, quit...\n");
        exit(0);
    }

    // get shared memory address
    if ((_pBlock = (SharedBlock *)shmat(_shmid, 0, 0)) == (void *)-1) {
        printf("Failed shmat(): %s.\n", strerror(errno));
    }
    printf("pBlock: %p, pBlock->buf1: %p, pBlock->buf2: %p\n", _pBlock, _pBlock->buf1, _pBlock->buf2);

    // get created process id
    if (shmctl(_shmid, IPC_STAT, &buf) == -1) {
        printf("Failed shmctl().\n");
    }
    else {
        printf("Protocol process: %d.\n", buf.shm_cpid);
        _protoPid = buf.shm_cpid;
    }

    // do work here
    //printf("Shared: %s\n", _pBlock->buf1);
    //kill(buf.shm_cpid, SIGUSR1);
}

void CSocket::detachSharedMem()
{
    if (shmdt(_pBlock) == -1) {
        printf("Failed shmdt(): %s.\n", strerror(errno));
    }
}

int CSocket::init(int family, int type, int protocol)
{
    //_socketId   = getpid();

    //_family     = family;
    //_type       = type;
    //_protocol   = protocol;
    _sock.pid       = getpid();
    _sock.sockfd    = _sock.pid;
    _sock.family    = family;
    _sock.type      = type;
    _sock.protocol  = protocol;

    _sock.addr.s_addr   = 0;
    _sock.port          = 0;

    // Send to ProtoSocket create socket
    //Sock sock;
    //sock.pid = sock.sockfd = _socketId;
    //sock.family   = _family;
    //sock.type     = _type;
    //sock.protocol = _protocol;
    //sock.addr.s_addr = 0;
    //sock.port   = 0;

    SockPacket sockPkt;
    sockPkt.type = SockPktCreate;
    memcpy(sockPkt.data, &_sock, sizeof(Sock));

    // Copy to shared memory and notify this
    memcpy(_pBlock->buf2, &sockPkt, sizeof(Sock) + sizeof(SockPktT));
    kill(_protoPid, SIGUSR1);
    log(TAG "%s : kill signal SIGUSR1 to process %d.\n", __func__, _protoPid);

    pause();

    int result;
    if (sig == SIGUSR1) {
        result = *((int *)_pBlock->buf1);
    }
    else {
        result = -1;
    }

    printf("Created socket: %d\n", result);

    return result;

}

int CSocket::socket(int family, int type, int protocol)
{
    return init(family, type, protocol);

}

int CSocket::bind(const struct sockaddr* addr, socklen_t len)
{
    struct sockaddr_in bindAddr = *((struct sockaddr_in *)addr);

    _sock.addr = bindAddr.sin_addr;
    _sock.port = bindAddr.sin_port;

    SockPacket sockPkt;
    sockPkt.type = SockPktBind;

    memcpy(sockPkt.data, &_sock, sizeof(_sock));
    memcpy(_pBlock->buf2, &sockPkt, sizeof(SockPktT) + sizeof(Sock));

    kill(_protoPid, SIGUSR1);

    pause();

    if (sig == SIGUSR1) {
        int success = *((int *)_pBlock->buf1);
        if (success == 1) {
            return 0;
        }
        else {
            _sock.addr.s_addr = 0;
            _sock.port = 0;
            return -1;
        }
    }
    else {
        _sock.addr.s_addr = 0;
        _sock.port = 0;
        fprintf(stderr, "Not SIGUSR1 received\n");
        return -1;
    }
}

int CSocket::sendto(const char* buf, size_t len, int flags,
        const struct sockaddr* dstAddr, socklen_t addrlen) 
{
    // todo: Send to ProtoSocket send message
    //   data format: ProtoSocket{type, {SockData, buf}}
    //              or: ProtoSocket{type, {left buf}}
    SockDataHdr sockDataHdr;
    sockDataHdr.sockfd  = _sock.sockfd;
    sockDataHdr.dstAddr = *dstAddr;
    sockDataHdr.flag    = flags;
    sockDataHdr.len     = len;

    SockPacket sockPkt;
    sockPkt.type = SockPktSendTo;

    char *pData = sockPkt.data;

    memcpy(pData, &sockDataHdr, sizeof(SockDataHdr));
    pData += sizeof(SockDataHdr);

    int bufLeft = cSHMDataSize - sizeof(SockDataHdr);
    int dataLeft = len;
    
    while (dataLeft > 0) {
        int dataLen;

        if (bufLeft <= 0) {         // re-point to buffer start
            bufLeft = cSHMDataSize;
            pData = sockPkt.data;
        }

        if (dataLeft <= bufLeft) {
            dataLen = dataLeft;
        }
        else {
            dataLen = bufLeft;
        }

        memcpy(pData, buf, dataLen);

        pData       += dataLen;
        dataLeft    -= dataLen;
        bufLeft     -= dataLen;

        int bytes = pData - sockPkt.data + sizeof(SockPktT);
        printf("will copy %d bytes.\n", bytes);
        memcpy(_pBlock->buf2, &sockPkt, bytes);
        kill(_protoPid, SIGUSR2);
    }

    pause();

    int byteSend = -1;
    if (sig == SIGUSR2) {
        byteSend = *((int *)_pBlock->buf1);
    }

    printf("Send %d bytes.\n", byteSend);

    return byteSend;
}

int CSocket::recvfrom(char* buf, size_t len, int flags,
        struct sockaddr* srcAddr, socklen_t* addrlen)
{
    SockDataHdr dataHdr;
    dataHdr.sockfd  = _sock.sockfd;
    dataHdr.flag    = flags;
    dataHdr.len     = len;

    SockPacket sockPkt;
    sockPkt.type    = SockPktRecvFrom;

    memcpy(sockPkt.data, &dataHdr, sizeof(dataHdr));
    memcpy(_pBlock->buf2, &sockPkt, sizeof(SockPktT) + sizeof(dataHdr));
    kill(_protoPid, SIGUSR1);

    pause();

    // read data from ProtoSocket and set value-result parameters
    char *pData = _pBlock->buf1;
    SockDataHdr* rcvDataHdr = (SockDataHdr *)pData;

    struct sockaddr_in* fromAddr = (struct sockaddr_in *)&rcvDataHdr->srcAddr;
    *srcAddr = rcvDataHdr->srcAddr;
    *addrlen = sizeof(struct sockaddr);
    printf("Received data from %s:%d.\n", inet_ntoa(fromAddr->sin_addr), ntohs(fromAddr->sin_port));

    pData += sizeof(SockDataHdr);

    int dataLen = len;
    if (dataLen > rcvDataHdr->len) {
        dataLen = rcvDataHdr->len;
    }
    memcpy(buf, pData, dataLen);

    return dataLen;
}

int CSocket::close() 
{
    SockPacket sockPkt;
    sockPkt.type = SockPktClose;

    memcpy(sockPkt.data, &_sock, sizeof(Sock));
    memcpy(_pBlock->buf2, &sockPkt, sizeof(SockPktT) + sizeof(Sock));
    kill(_protoPid, SIGUSR1);

    return 0;
}

int CSocket::connect(const struct sockaddr* addr, socklen_t len)
{
    return 0;
}

int CSocket::send(const char * buf, size_t len, int flag)
{
    return 0;
}

int CSocket::recv(char * buf, size_t len, int flag)
{
    return 0;
}

int CSocket::listen(int backlog)
{
    return 0;
}

CSocket * CSocket::accept(struct sockaddr * sockaddr, socklen_t * addrlen)
{
    // here should get your notice since shared memory used, fix the code
    // 
    // there is one way, add another constructor with more parameter
    // 
    // but, actually, shared memory by attach method won't be error, maybe you don't have
    // to change any thing
    return new CSocket();
}

