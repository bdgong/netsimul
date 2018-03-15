#pragma once 

#include "SharedBlock.h"
#include "InetSocket.h"
#include "packet.h"

#include <map>
#include <set>

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

        void onConnectFinish();
        uint32_t selectFD();
         
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

        int _shmid;          // shared memory identifier
        SharedBlock *_pBlock;// shared block

        std::map<int, InetSock> _sockPool;        // created sockets, <sockfd, InetSock>
        std::set<InetSock *> _pendingSocks;       // pending recvfrom sockets

};

