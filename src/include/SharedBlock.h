#pragma once

#include <arpa/inet.h>

const char * const cKeyPath = "/home/bdg/.netsimul";   // this file must exist
const int cKeyID = 17;

const unsigned int cSHMSize = 8192;
const unsigned int cSHMBufSize = 4096;
const unsigned int cSHMDataSize = 4092;

/*
 * struct sharedblock - a data structure between ProtocolSocket and AppSocket 
 *
 * @buf1 - ProtocolSocket buffer
 * @buf2 - AppSocket buffer
 * */
typedef struct sharedblock {
    char buf1[cSHMBufSize];         // address is &sharedblock
    char buf2[cSHMBufSize];         // address is buf1 + 4096
} SharedBlock;

typedef enum sockpktype {
    SOCK_CREATE = 1,
    SOCK_BIND,
    SOCK_LISTEN,
    SOCK_CONNECT,
    SOCK_ACCEPT,
    SOCK_SEND,
    SOCK_SENDTO,
    SOCK_RECV,
    SOCK_RECVFROM,
    SOCK_CLOSE,
} SockPktType;

typedef enum socketstate {
    SS_FREE = 0,
    SS_UNCONNECTED,
    SS_CONNECTED,
    SS_CONNECTING,
    SS_DISCONNECTING
} SocketState;

/*
 * struct sockpacket - this data structure will save to buf1 or buf2 after conversion
 * */
typedef struct sockpacket {
    SockPktType type;                  // this field must be the first member
    char data[cSHMBufSize - 4];
} SockPacket;

/////////////// start of sockpacket.data structures ///////////////

typedef struct tagSock {
    int sockfd;         // socket file descriptor
    int pid;            // process id
    int family;
    int type;
    int protocol;
    struct in_addr addr;// socket bind address
    uint16_t port;      // socket bind port
    struct in_addr peerAddr;// peer socket address
    uint16_t peerPort;      // peer socket port
    SocketState state;  // connection state

    tagSock() 
    {
        sockfd = pid = family = type = protocol = 0;
        port = peerPort = 0;
        addr.s_addr = peerAddr.s_addr = 0;
        state = SS_UNCONNECTED;
    }

} Sock;

typedef struct tagSockDataHdr {
    int sockfd;
    struct sockaddr srcAddr;            // source address
    struct sockaddr dstAddr;            // destination address
    int flag;           // flag 
    int len;            // data length
} SockDataHdr;

/////////////// end of sockpacket.data structures   ///////////////

