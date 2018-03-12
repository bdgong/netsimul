#pragma once 

#include "SharedBlock.h"
#include <map>
#include <set>

#include "packet.h"

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
        unsigned short selectPort();

        void newConnection();
        void onConnectFinish();

        int _shmid;          // shared memory identifier
        SharedBlock *_pBlock;// shared block

        std::map<int, Sock> _sockPool;          // created sockets, <sockfd, Sock>
        //std::map<int, int> _pendingSocks;       // pending recvfrom sockets, <sockfd, port>
        std::set<Sock *> _pendingSocks;       // pending recvfrom sockets, <sockfd, port>

};

