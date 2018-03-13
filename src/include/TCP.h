#pragma once

#include "tcp.h"
#include "packet.h"
#include "InetSocket.h"
#include "Network.h"

class CNetwork;

class CTCP
{
    public:
        static CTCP * instance()
        {
            static CTCP inst;
            return &inst;
        }

        ~CTCP();

        void init();

        void connect(InetSock *sk);
        void listen();
        void accept();

    private:
        CTCP(const CTCP&);
        CTCP & operator=(const CTCP&);

        CTCP() : _isInited(false)
        {
        }

        CNetwork *_network;
        bool _isInited;
};

