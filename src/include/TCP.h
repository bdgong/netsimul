#pragma once

#include "tcp.h"
#include "ProtoSocket.h"
#include "InetSocket.h"
#include "Network.h"
#include "BaseIO.h"
#include <map>
#include <string>

typedef std::map<std::string, InetConnSock> ConnMap; // connections, <localAddr.localPort-peerAddr.peerPort, InetConnSock>
typedef std::map<uint16_t, InetSock*> InetSockMap;   // listen sockets, <port, InetSock*> 

class CNetwork;
class CProtoSocket;

class CTCP : public CBaseIO
{
    public:
        static CTCP * instance()
        {
            static CTCP inst;
            return &inst;
        }

        ~CTCP();

        void init();
        void send(packet_t *pkt);
        void received(packet_t *pkt);

        void connect(InetSock *sk);
        void listen();
        void accept();

    private:
        CTCP(const CTCP&);
        CTCP & operator=(const CTCP&);

        CTCP() { }

        /*
         * Return the key(or name) of a connection.
         * */
        std::string keyOf(InetConnSock *ics);
        std::string keyOf(struct in_addr localAddr, uint16_t localPort, struct in_addr peerAddr, uint16_t peerPort);
        InetConnSock * newConnection(InetConnSock *ics);

        InetSockMap _listenPool;
        ConnMap _connPool; 
        CProtoSocket *_protoSock;
        CNetwork *_network;
};

