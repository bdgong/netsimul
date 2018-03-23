#pragma once

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <memory>
#include "SharedBlock.h"

class CSocket
{
    public:
        CSocket();
        ~CSocket();

        int socket(int family, int type, int protocol);
        
        /*
         * Bind socket with address @sockaddr
         * */
        int bind(const struct sockaddr *sockaddr, socklen_t addrlen);

        /*
         * Connect to address @sockaddr
         * */ 
        int connect(const struct sockaddr *sockaddr, socklen_t addrlen);

        /*
         * Send to connected peer address
         *
         * @buf The data to send
         * @len The data length in bytes to send
         * */
        int send(const char * buf, size_t len, int flags);

        /*
         * Receive data from connected peer address, default timeout is 3 seconds.
         *
         * @buf The buffer used to stored received data 
         * @len Maximum bytes to receive
         * */
        int recv(char * buf, size_t len, int flags);

        /*
         * @return The number of bytes sent.  On error, -1 is returned
         * */
        int sendto(const char* buf, size_t len, int flags,
                const struct sockaddr* dstAddr, socklen_t addrlen);

        /*
         * @return The  number  of bytes received, or -1 if an error occurred.
         * */
        int recvfrom(char* buf, size_t len, int flags,
                struct sockaddr* srcAddr, socklen_t* addrlen);

        /*
         * Set this socket to listen mode
         *
         * @backlog The maximum client might in queue 
         * @return On success, zero is returned.  On error, -1 is returned
         * */
        int listen(int backlog);

        std::unique_ptr<CSocket> accept(struct sockaddr * sockaddr, socklen_t * addrlen);

        int shutdown();

        int close();

        /*
         * Return file descriptor of this socket
         * */
        int getFD()
        {
            return _sock.sockfd;
        }
        // 
    private:
        // 
        CSocket(const CSocket&);            // prevent copy
        CSocket & operator= (const CSocket&);// prevent assign

        /*
         * Do socket create
         * */
        int init(int family, int type, int protocol);

        /*
         * Attach and detach shared memory
         * */
        void attachSharedMem();
        void detachSharedMem();

        /*
         * Wait protocols stack reply
         *
         * @return Theorically, on success, 1 is returned, otherwise return 0 !!!
         * */
        int waitForSuccess(int signo);

        SockDataHdr makeDataHeader(size_t len, int flag);

        int _shmid;          // shared memory identifier
        SharedBlock *_pBlock;// shared block
        int _protoPid;          // protocol process id

        Sock _sock;
        //int _socketId;          // might use process id
        //int _family;
        //int _type;
        //int _protocol;
};

