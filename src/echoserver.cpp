/*
 * Echo server.
 *
 * Repeat received message to client.
 *
 * date: Sat 11 Nov 2017 09:58:27 
 * */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "echoapp.h"

class CEchoServer {
    private:
        struct sockaddr_in _svraddr;
        int _svrsock;
        uint16_t _port;

    public:
        CEchoServer() :
            _port(cDefaultPort)
        {
            init();
        }
        CEchoServer(uint16_t port) : 
            _port(port)
        {
            init();
        }

        ~CEchoServer() 
        {
            close(_svrsock);
        }

        void init();
        void run();
        void handleClient(const struct sockaddr_in *cliaddr, const char *msg, size_t bytes_recv);

        static uint16_t cDefaultPort;

};

uint16_t CEchoServer::cDefaultPort = 1314;

void CEchoServer::init() 
{

    _svraddr.sin_family         = AF_INET;
    _svraddr.sin_port           = htons(_port);
    _svraddr.sin_addr.s_addr    = INADDR_ANY;

    if( (_svrsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        fprintf(stderr, "socket error.\n");
        exit(EXIT_FAILURE);
    }

    if ( bind(_svrsock, (struct sockaddr *)&_svraddr, sizeof(_svraddr)) < 0 ) {
        fprintf(stderr, "bind socket address failed.\n");
        exit(EXIT_FAILURE);
    }

}

void CEchoServer::run()
{

    char buf[cMaxBufSize];
    struct sockaddr_in cliaddr;
    socklen_t clilen = sizeof(cliaddr);         // this is important for the first time received ip address none zero.
    while(true) {
        int bytes_recv = recvfrom(_svrsock, buf, cMaxBufSize, 0, 
                (struct sockaddr *)&cliaddr, &clilen);

        if(bytes_recv > 0) {
            buf[bytes_recv] = '\0';
            handleClient(&cliaddr, buf, bytes_recv);
        }
    }

}

void CEchoServer::handleClient(const struct sockaddr_in *cliaddr, const char *msg, size_t bytes_recv)
{

    fprintf(stdout, "%s:%u > %s\n", inet_ntoa(cliaddr->sin_addr), ntohs(cliaddr->sin_port), msg);

    int bytes_send = sendto(_svrsock, msg, bytes_recv, 0, 
            (const struct sockaddr *)cliaddr, sizeof(struct sockaddr_in)); 
    if(bytes_send <= 0) {
        fprintf(stderr, "reply to %s failed.\n", inet_ntoa(cliaddr->sin_addr));
    }

}

void print_usage() 
{

    printf("Usage:\nechoserver <port>\n\n");

}

int main(int argc, char *argv[]) {

    uint16_t port = CEchoServer::cDefaultPort;
    if(argc > 1) {
        port = atoi(argv[1]);
    }

    CEchoServer echoserver(port);
    printf("echo server started at port %u.\n\n", port);
    echoserver.run();
    return 0;
}

