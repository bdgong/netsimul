/*
 * DemoEchoServer - TCP Demo
 *
 * Receive something from client and reply the same thing.
 * */

#include "Socket.h"
#include <string>
#include <cstring>
#include <time.h>

const int cPort = 2333;
const int cBufSize = 4096;
const int cBackLog = 10;

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: %s <ip> <port>.\n", argv[0]);
        return (0);
    }

    int sockfd;
    struct sockaddr_in svrAddr;
    CSocket socket;

    if ((sockfd = socket.socket(AF_INET, SOCK_STREAM, 0)) == -1) {
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

    // bind local address
    if (socket.bind((struct sockaddr*)&svrAddr, sizeof(struct sockaddr)) == -1) {
        fprintf(stderr, "Failed bind().\n");
        return 0;
    }
    else {
        printf("%s run with %s:%d.\n\n", argv[0], argv[1], ntohs(svrAddr.sin_port));
    }

    // start listen 
    socket.listen(cBackLog);

    struct sockaddr_in client;
    unsigned int addrlen = sizeof(client);

    char buf[cBufSize];
    while (true) {
        CSocket * clientSocket = socket.accept((struct sockaddr*)&client, &addrlen);

        if (clientSocket->getFD() > 0) {
            int bytesRecv = clientSocket->recv(buf, cBufSize, 0);
            if (bytesRecv > 0) {
                // print received message
                buf[bytesRecv] = '\0';
                printf("Server received: %s.\n", buf);

                // reply client
                clientSocket->send(buf, bytesRecv, 0);
                printf("Replied client: %s.\n", buf);
            }
            else {
                printf("Server receive error, bytesRecv = %d.\n", bytesRecv);
            }
        }
        else {
            fprintf(stderr, "Failed accept connection.\n");
        }

        // think about the programming model more, it's not the best idea to do this
        delete clientSocket;
    }

    return 0;

}

