#pragma once

#include "SharedBlock.h"
#include "packet.h"
#include <string>
#include <list>
#include <memory>

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
} InetSockState;

/*
 * struct InetSock - Internet socket
 * */
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
    int backlog;
} InetSock;

typedef std::list<std::shared_ptr<packet_t>> PacketQueue;

typedef struct tagICSWindow 
{
    uint16_t size;          // window size
    uint32_t lastSeq;
    uint32_t lastAck;
    uint32_t nextSeq;
    uint32_t nextAck;
    uint32_t lower;         // window lower bound
    uint32_t upper;         // window upper bound
} ICSWindow;

/*
 * struct InetConnSock - Internet connection based socket
 * */
typedef struct tagInetConnSock
{
    InetSock _inetSock;
#define ics_sockfd _inetSock.sk_sockfd
#define ics_pid _inetSock.sk_pid
#define ics_family _inetSock.sk_family
#define ics_type _inetSock.sk_type
#define ics_protocol _inetSock.sk_protocol
#define ics_addr _inetSock.sk_addr
#define ics_port _inetSock.sk_port
#define ics_peerAddr _inetSock.sk_peerAddr
#define ics_peerPort _inetSock.sk_peerPort
#define ics_state _inetSock.sk_state
    ICSWindow sendWin,
              recvWin;
    PacketQueue sendQueue,
                recvQueue;

    tagInetConnSock() 
    {
        memset(&sendWin, 0 , sizeof(ICSWindow));
        memset(&recvWin, 0 , sizeof(ICSWindow));
    }

} InetConnSock;

