/*
 * DemoTimeClient - UDP Demo
 *
 * Send "time" to time server, print the feedback.
 * */
#include <cstdio>
#include <cstring>
#include <string>
#include "Socket.h"

const char * const cDstAddrStr  = "211.67.27.254";
const unsigned short cDstPort   = 1618;

void usage(const char *appName) 
{
    printf("Default address use %s:%d\n", cDstAddrStr, cDstPort);
    printf("To change it use addtional parameters:\n\t%s <ip> <port>\n", appName);
    printf("\n----------\n\n");
}

int main(int argc, char *argv[])
{
    usage(argv[0]);

    // create a socket
    CSocket socket;
    int sockfd;
    if ( (sockfd = socket.socket(AF_INET, SOCK_DGRAM, 0)) <= 0) {
        fprintf(stderr, "Failed socket().\n");
        return -1;
    }

    // set target address
    struct sockaddr_in dstAddr;
    dstAddr.sin_family = AF_INET;

    char dstAddrStr[20];
    unsigned short dstPort;

    strncpy(dstAddrStr, cDstAddrStr, strlen(cDstAddrStr) + 1);
    dstPort = cDstPort;
    if (argc > 1) {
        strncpy(dstAddrStr, argv[1], strlen(argv[1]) + 1);
    }
    if (argc > 2) {
        dstPort = std::stoi(argv[2]);
    }

    if (inet_aton(dstAddrStr, &dstAddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", dstAddrStr);
        return -1;
    }
    dstAddr.sin_port = htons(dstPort);

    printf("Target %s:%d.\n", dstAddrStr, dstPort);

    // send
    const char *text = "time";
    int len = strlen(text);
    int byteSend = socket.sendto(text, len, 0, (const sockaddr*)&dstAddr, sizeof(dstAddr));

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

