#pragma once

#include "tcp.h"
#include "ProtoSocket.h"
#include "InetSocket.h"
#include "Network.h"
#include "BaseIO.h"
#include <map>
#include <string>

typedef std::map<std::string, InetConnSock> ConnMap; // connections, <localAddr.localPort-peerAddr.peerPort, InetConnSock>
typedef std::map<uint16_t, InetSock*> InetSockMap;  // listen sockets, <port, InetSock*>
                                                    // actually, value is a pointer to CProtoSocket member _sockPool's
                                                    // element

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
        int send(packet_t *pkt);
        int received(packet_t *pkt);

        void connect(InetSock *sk);
        void listen(InetSock *sk);

        /*
         * Close a connection
         *
         * @name The connection name, can be contructed by keyOf()
         * */
        void close(std::string name);

        /*
         * Return the key(or name) of a connection.
         * */
        static std::string keyOf(InetConnSock *ics);
        static std::string keyOf(struct in_addr localAddr, uint16_t localPort, struct in_addr peerAddr, uint16_t peerPort);

    private:
        CTCP(const CTCP&);
        CTCP & operator=(const CTCP&);

        CTCP() { }

        InetConnSock * newConnection(InetConnSock *ics);
        void doSend(InetConnSock *ics);
        void __doSend(packet_t *packet, InetConnSock *ics, uint8_t flags, uint8_t *buf, uint32_t size);

        /*
         * Send a tcp segment without payload
         *
         * @packet The allocated packet
         * @ics The connection
         * @flags The tcp header flags
         * */
        void sendNoData(packet_t *packet, InetConnSock *ics, uint8_t flags);

        void recvEstablished(InetConnSock *ics, packet_t *packet, tcphdr_t *tcphdr);
        void recvStateProcess(InetConnSock *ics, packet_t *packet, tcphdr_t *tcphdr);
        void recvListen(InetSock *ics, packet_t *packet, tcphdr_t *tcphdr);

        InetSockMap _listenPool;
        ConnMap _connPool; 
        CProtoSocket *_protoSock;
        CNetwork *_network;
};

