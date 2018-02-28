#pragma 

const char *cKeyPath = "/home/bdg/.netsimul";
const int cKeyID = 17;

const unsigned int cSHMSize = 8192;
const unsigned int cSHMBufSize = 4096;

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
    SockPktT type;
    char data[cSHMBufSize - 4];
} SockPacket;

/////////////// start of sockpacket.data structures ///////////////

typedef struct sockcreate {
    int pid;            // process id
    int sockfd;         // socket file descriptor
    int family;
    int type;
    int protocol;
} SockCreate;

/////////////// end of sockpacket.data structures   ///////////////

