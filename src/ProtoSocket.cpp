#include "ProtoSocket.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>

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
    init();
}

CProtoSocket::~CProtoSocket()
{
    destroySharedMem();
}

void CProtoSocket::init()
{
    createSharedMem();
}

void CProtoSocket::createSharedMem()
{
    key_t key;

    if ((key = ftok(cKeyPath, cKeyID)) == -1) {
        fprintf(stderr, "Failed ftok().\n");
    }

    if ((_shmid = shmget(key, cSHMSize, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR)) == -1) {
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
        // do work here
        //
    }

    printf("Protocol exit...\n");
}

void CProtoSocket::handleSockRequest()
{
    SockPacket *sockPkt;

    sockPkt = (SockPacket *)_pBlock->buf2;
    switch (sockPkt->type) {
        case SockPktCreate: 
            {
                SockCreate *sockCreate;
                sockCreate = (SockCreate *)sockPkt->data;

                printf("pid: %d, family: %d, type: %d, protocol: %d\n"
                        , sockCreate->pid, sockCreate->family, sockCreate->type
                        , sockCreate->protocol);
                break;
            }
        default:
            break;
    }

}

