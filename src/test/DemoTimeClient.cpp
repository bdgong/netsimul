/*
 * Send "time" to time server, print the feedback.
 * */
#include <cstdio>
#include <cstring>
#include "Socket.h"

const char *dstAddrStr = "211.67.27.254";
const short dstPort = 1618;

int main()
{
    CSocket socket;
    int sockfd;
    if ( (sockfd = socket.socket(AF_INET, SOCK_DGRAM, 0)) <= 0) {
        fprintf(stderr, "Failed socket().\n");
        return -1;
    }

    struct sockaddr_in dstAddr;
    dstAddr.sin_family = AF_INET;
    if (inet_aton(dstAddrStr, &dstAddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", dstAddrStr);
        return -1;
    }
    dstAddr.sin_port = htons(dstPort);

    const char *text = "time";
    int byteSend = socket.sendto(text, strlen(text), 0, (const sockaddr*)&dstAddr, sizeof(dstAddr));

    char buf[1024 + 1];
    socklen_t socklen = sizeof(dstAddr);
    if (byteSend > 0) {
        int byteRecv = socket.recvfrom(buf, 1024, 0, (struct sockaddr *)&dstAddr, &socklen);

        if (byteRecv > 0) {
            buf[byteRecv] = '\0';
            printf("> %s\n", buf);
        }
        else {
            fprintf(stderr, "Failed receive.\n");
        }
    }
    else {
        fprintf(stderr, "Failed sendto().\n");
    }

    return 0;
}

