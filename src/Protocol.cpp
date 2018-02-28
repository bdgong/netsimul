#include "ProtoSocket.h"
#include <cstdio>

int main()
{
    CProtoSocket protoSocket;
    protoSocket.run();

    printf("Protocol process exiting...\n");

    return 0;
}

