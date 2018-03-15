#pragma once 

#include "SharedBlock.h"
#include "InetSocket.h"
#include "packet.h"

#include <map>
#include <set>
#include <string>

typedef std::map<std::string, InetConnSock*> ConnPMap; // connections, <localAddr.localPort-peerAddr.peerPort, InetConnSock*>
                                                    // actually, value is a pointer to TCP member _connPool's element

class CProtoSocket
{
    public:
        static CProtoSocket* instance()
        {
            static CProtoSocket inst;
            return &inst;
        }
        ~CProtoSocket();

        void run();

        /*
         * Received packet from protocol
         * */
        void received(const packet_t *pkt);

        /*
         * Called by TCP when a new connection @ics is arrived
         *
         * @name Connection name
         * @ics The connection 
         *
         * To be honest, this method can be avoided
         * */
        void connectFinished(std::string name, InetConnSock *ics);

        uint32_t selectFD();

        /*
         * Accepted an established connection from TCP
         *
         * @name Connection name
         * @ics The connection 
         * */
        void accept(std::string name, InetConnSock *ics);
         
    private:
        // 
        CProtoSocket();
        CProtoSocket(const CProtoSocket&);
        CProtoSocket & operator=(const CProtoSocket&);

        /*
         * Create and detach shared memory
         * */
        void createSharedMem();
        void destroySharedMem();

        void handleSockRequest();

        void handleCreate(SockPacket *sockPkt);
        void handleBind(SockPacket *sockPkt);
        void handleSendTo(SockPacket *sockPkt);
        void handleRecvFrom(SockPacket *sockPkt);
        void handleClose(SockPacket *sockPkt);
        void handleListen(SockPacket *sockPkt);
        void handleConnect(SockPacket *sockPkt);
        void handleAccept(SockPacket *sockPkt);

        /*
         * Random select an unused port
         * */
        uint16_t selectPort();

        void setLocalAddr(InetSock * sk);

        /*
         * Notify socket a given signal
         *
         * @success An int value when 1 for success, 0 for failed
         * @pid The process id
         * @signo The signal number
         * @funcName The calling function name
         * */
        void afterHandle(int success, int pid, int signo, const char * const funcName);
        void afterHandle(int pid, int signo, const char * const funcName);

        std::set<uint16_t> _pendingAccept;
        ConnPMap _connPPool; // connection pointers map
        std::map<int, InetSock> _sockPool;        // created sockets, <sockfd, InetSock>
        std::set<InetSock *> _pendingSocks;       // pending recvfrom sockets

        int _shmid;          // shared memory identifier
        SharedBlock *_pBlock;// shared block
};

