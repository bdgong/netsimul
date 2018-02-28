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

int sig;            // received signal

void handler1(int signo)
{
    //printf("Received signal: %d.\n", signo);
    sig = signo;
}

void handler2(int signo)
{
    sig = signo;
    //printf("Received signal: %d.\n", signo);
}



CSocket::CSocket() : _socketId(0)
{
    attachSharedMem();
}

CSocket::~CSocket()
{
    detachSharedMem();
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
    _socketId   = getpid();

    _family     = family;
    _type       = type;
    _protocol   = protocol;

    // Send to ProtoSocket create socket
    SockCreate sockCreate;
    sockCreate.pid = sockCreate.sockfd = _socketId;
    sockCreate.family   = _family;
    sockCreate.type     = _type;
    sockCreate.protocol = _protocol;

    SockPacket sockPkt;
    sockPkt.type = SockPktCreate;
    memcpy(sockPkt.data, &sockCreate, sizeof(SockCreate));

    // Copy to shared memory and notify this
    memcpy(_pBlock->buf2, &sockPkt, sizeof(SockCreate) + sizeof(SockPktT));
    kill(_protoPid, SIGUSR1);

    return _socketId;

}

int CSocket::socket(int family, int type, int protocol)
{
    return init(family, type, protocol);

}

int CSocket::sendto(const char* buf, size_t len, int flags,
        const struct sockaddr* dstAddr, socklen_t addrlen) 
{
    // todo: Send to ProtoSocket send message
    return 0;
}

int CSocket::recvfrom(char* buf, size_t len, int flags,
        struct sockaddr* srcAddr, socklen_t* addrlen)
{
    return 0;
}

