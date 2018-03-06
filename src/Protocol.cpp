#include "ProtoSocket.h"

#include <cstdio>

int main()
{
    printf("Protocol process starting...\n");

    CProtoSocket* protoSocket = CProtoSocket::instance();
    protoSocket->run();

    printf("Protocol process exiting...\n");

    return 0;
}

