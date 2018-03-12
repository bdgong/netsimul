#pragma once

#include "SharedBlock.h"

/*
 * enum use capital, remember this rule
 * */
typedef enum inetsockstate {
    CLOSED = 0,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    TIME_WAIT,
    LISTEN,
    SYN_RCVD,
    CLOSE_WAIT,
    LAST_ACK
} InetSockState;

typedef struct tagInetSock
{
    Sock sock;
#define sockfd sock.sockfd
#define pid sock.pid
#define family sock.family
#define type sock.type
#define protocol sock.protocol
#define addr sock.addr
#define port sock.port
#define peerAddr sock.peerAddr
#define peerPort sock.peerPort
    InetSockState state;
} InetSock;

