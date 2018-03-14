#pragma once

#include "tcp.h"
#include "InetSocket.h"
#include "Network.h"
#include "BaseIO.h"

class CNetwork;

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

        CNetwork *_network;
};

