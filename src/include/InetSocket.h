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
    LAST_ACK,

    UNCONNECTED,
    CONNECTING,
    DISCONNECTING
} InetSockState;

typedef struct tagInetSock
{
    Sock _sock;
#define sk_sockfd _sock.sockfd
#define sk_pid _sock.pid
#define sk_family _sock.family
#define sk_type _sock.type
#define sk_protocol _sock.protocol
#define sk_addr _sock.addr
#define sk_port _sock.port
#define sk_peerAddr _sock.peerAddr
#define sk_peerPort _sock.peerPort
    InetSockState sk_state;
} InetSock;

