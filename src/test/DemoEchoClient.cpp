
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

    // set server address
    struct sockaddr_in svrAddr;
    svrAddr.sin_family = AF_INET;

    char svrAddrStr[20];
    unsigned short svrPort;

    strncpy(svrAddrStr, cDstAddrStr, strlen(cDstAddrStr) + 1);
    svrPort = cDstPort;
    if (argc > 1) {
        strncpy(svrAddrStr, argv[1], strlen(argv[1]) + 1);
    }
    if (argc > 2) {
        svrPort = std::stoi(argv[2]);
    }

    if (inet_aton(svrAddrStr, &svrAddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", svrAddrStr);
        return -1;
    }
    svrAddr.sin_port = htons(svrPort);

    printf("Target %s:%d.\n", svrAddrStr, svrPort);

    // connect
    printf("Connecting server...");
    int success = socket.connect((const sockaddr*)&svrAddr, sizeof(svrAddr));

    if (success != -1) {
        // send
        printf("connected, will send 'hello'.\n");
        const char *text = "hello";
        int len = strlen(text);
        int byteSend = socket.send(text, len, 0);

        if (byteSend > 0) {
            printf("Send out 'hello'.\n");
            char buf[1024 + 1];
            socklen_t socklen = sizeof(svrAddr);
            printf("Receiving...\n");
            int byteRecv = socket.recv(buf, 1024, 0);

            if (byteRecv > 0) {
                buf[byteRecv] = '\0';
                printf("received: %s\n", buf);
            }
            else {
                printf("failed recv().\n");
            }
        }
        else {
            printf("Send out 'hello' failed.\n");
        }

        socket.close();
    }
    else {
        printf("failed connect().\n");
    }

    return 0;

}

