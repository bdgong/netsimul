/*
 * DemoTimeServer - UDP Demo
 *
 * Receive client message and reply current system time.
 * */

#include "Socket.h"
#include <string>
#include <cstring>
#include <time.h>

const int cPort = 1618;
const int cBufSize = 4096;

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: %s <ip> <port>.\n", argv[0]);
        return (0);
    }

    int sockfd;
    struct sockaddr_in svrAddr;
    CSocket socket;

    if ((sockfd = socket.socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        printf("Failed socket().\n");
        return 0;
    }

    svrAddr.sin_family = AF_INET;
    inet_aton(argv[1], &svrAddr.sin_addr);

    if (argc > 2) {
        svrAddr.sin_port = htons(std::stoi(argv[2]));
    }
    else {
        svrAddr.sin_port = htons(cPort);
    }

    if (socket.bind((struct sockaddr*)&svrAddr, sizeof(struct sockaddr)) == -1) {
        fprintf(stderr, "Failed bind().\n");
        return 0;
    }
    else {
        printf("%s run with %s:%d.\n\n", argv[0], argv[1], ntohs(svrAddr.sin_port));
    }

    struct sockaddr_in client;
    unsigned int addrlen = sizeof(client);

    char buf[cBufSize];
    while (true) {
        int bytesRecv = socket.recvfrom(buf, cBufSize, 0, (struct sockaddr*)&client, &addrlen);
        if (bytesRecv > 0) {
            // print received message
            buf[bytesRecv] = '\0';
            printf("Server received: %s.\n", buf);

            // reply client
            time_t now = time(NULL);
            snprintf(buf, cBufSize, "%.24s\r\n", ctime(&now));
            socket.sendto(buf, strlen(buf), 0, (struct sockaddr*)&client, sizeof(struct sockaddr));
            printf("Replied current time.\n");
        }
        else {
            printf("Server receive error, bytesRecv = %d.\n", bytesRecv);
        }
    }

    return 0;

}

