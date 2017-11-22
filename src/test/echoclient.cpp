/*
 * Echo client
 *
 * Accept user's input, send to server, then display the reply.
 *
 * date: Sat 11 Nov 2017 11:32:15 
 * */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "echoapp.h"

class CEchoClient
{
    private:
        struct sockaddr_in _svraddr, _cliaddr; 
        int _clisock;
        const char *_svraddrstr;
        int _svrport, _cliport;

    public:
        CEchoClient() :
            _svraddrstr(cDefaultSvrAddr), _svrport(cDefaultSvrPort)
        {
            init();
        }

        CEchoClient(const char *svraddr, uint16_t svrport) :
            _svraddrstr(svraddr), _svrport(svrport)
        {
            init();
        }

        ~CEchoClient()
        {
            close(_clisock);
        }

        void init();
        void run();

        static uint16_t cDefaultSvrPort;
        static const char *const cDefaultSvrAddr;
};

uint16_t CEchoClient::cDefaultSvrPort = 1314;
const char *const CEchoClient::cDefaultSvrAddr = "127.0.0.1";

void CEchoClient::init()
{

    //create client socket
    if ( (_clisock = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ) {
        fprintf(stderr, "socket error.\n");
        exit(EXIT_FAILURE);
    }

    //set server address
    _svraddr.sin_family = AF_INET;
    if ( inet_aton(_svraddrstr, &_svraddr.sin_addr) == 0 ) {
        fprintf(stderr, "Invalid address: %s\n", _svraddrstr);
        exit(EXIT_FAILURE);
    }
    _svraddr.sin_port = htons(_svrport);

}

void CEchoClient::run() 
{

    char buf[cMaxBufSize];
    socklen_t svraddrlen = sizeof(_svraddr);
    while (true) {
        printf("> ");
        fgets(buf, cMaxBufSize, stdin);

        int bytes_send = sendto(_clisock, buf, strlen(buf), 0,
                (const struct sockaddr*)&_svraddr, sizeof(_svraddr));
        if(bytes_send > 0) {
            // send successfully, read reply
            int bytes_recv = recvfrom(_clisock, buf, cMaxBufSize, 0,
                    (struct sockaddr*)&_svraddr, &svraddrlen);
            if(bytes_recv > 0) {
                buf[bytes_recv] = '\0';
                printf("< %s\n", buf);
            }
            else {
                fprintf(stderr, "< receive failed.\n");
            }
        }
    }

}

void print_usage() 
{

    printf("Usage:\nechoclient <server_ip> <server_port>\n\n");

}

int main(int argc, char *argv[]) { 

    const char *svraddr       = CEchoClient::cDefaultSvrAddr;
    uint16_t svrport    = CEchoClient::cDefaultSvrPort;

    if(argc > 2) {
        svraddr = argv[1];
        svrport = atoi(argv[2]);
    }
    else if(argc > 1) {
        svraddr = argv[1];
    }
    else {
        fprintf(stdout, "Use default address and port.\n");
    }

    printf("Server %s:%u\n", svraddr, svrport);
    printf("Enter message to echo.\n\n");

    CEchoClient echoclient(svraddr, svrport);
    echoclient.run();

    return 0;
}


