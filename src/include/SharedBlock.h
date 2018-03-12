#pragma once

#include <arpa/inet.h>

const char * const cKeyPath = "/home/bdg/.netsimul";   // this file must exist
const int cKeyID = 17;

const unsigned int cSHMSize = 8192;
const unsigned int cSHMBufSize = 4096;
const unsigned int cSHMDataSize = 4094;

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

typedef unsigned short SockPktT;

enum sockpktype {
    SockPktCreate = 1,
    SockPktBind,
    SockPktListen,
    SockPktConnect,
    SockPktAccept,
    SockPktSend,
    SockPktSendTo,
    SockPktRecv,
    SockPktRecvFrom,
    SockPktClose
};

/*
 * struct sockpacket - this data structure will save to buf1 or buf2 after conversion
 * */
typedef struct sockpacket {
    SockPktT type;                  // this field must be the first member
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
} Sock;

typedef struct tagSockDataHdr {
    int sockfd;
    struct sockaddr srcAddr;            // source address
    struct sockaddr dstAddr;            // destination address
    int flag;           // flag 
    int len;            // data length
} SockDataHdr;

/////////////// end of sockpacket.data structures   ///////////////

