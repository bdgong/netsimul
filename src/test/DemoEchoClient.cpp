
/*
 * DemoEchoClient - TCP Demo
 *
 * Send something like "hello" to echo server, print the reply.
 * */
#include <cstdio>
#include <cstring>
#include <string>
#include "Socket.h"

const char * const cDstAddrStr  = "211.67.27.254";
const unsigned short cDstPort   = 2333;

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
    if ( (sockfd = socket.socket(AF_INET, SOCK_STREAM, 0)) <= 0) { 
        fprintf(stderr, "Failed socket().\n");
        return -1;
    }

    // set target address
    struct sockaddr_in svrAddr;
    svrAddr.sin_family = AF_INET;

    char svrAddrStr[20];
    unsigned short dstPort;

    strncpy(svrAddrStr, cDstAddrStr, strlen(cDstAddrStr) + 1);
    dstPort = cDstPort;
    if (argc > 1) {
        strncpy(svrAddrStr, argv[1], strlen(argv[1]) + 1);
    }
    if (argc > 2) {
        dstPort = std::stoi(argv[2]);
    }

    if (inet_aton(svrAddrStr, &svrAddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", svrAddrStr);
        return -1;
    }
    svrAddr.sin_port = htons(dstPort);

    printf("Target %s:%d.\n", svrAddrStr, dstPort);

    // connect
    int success = socket.connect((const sockaddr*)&svrAddr, sizeof(svrAddr));

    if (success != -1) {
        // send
        printf("Connected server, send 'hello'.\n");
        const char *text = "hello";
        int len = strlen(text);
        int byteSend = socket.send(text, len, 0);

        if (byteSend > 0) {
            char buf[1024 + 1];
            socklen_t socklen = sizeof(svrAddr);
            int byteRecv = socket.recv(buf, 1024, 0);

            if (byteRecv > 0) {
                buf[byteRecv] = '\0';
                printf("Received: %s\n", buf);
            }
            else {
                fprintf(stderr, "Receive from server failed.\n");
            }
        }
        else {
            fprintf(stderr, "Send server 'hello' failed.\n");
        }

        socket.close();
    }
    else {
        fprintf(stderr, "Failed connect().\n");
    }

    return 0;

}

