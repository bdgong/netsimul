#pragma once

#include <arpa/inet.h>
#include <netinet/ip.h>
#include "SharedBlock.h"

class CSocket
{
    public:
        CSocket();
        ~CSocket();

        int socket(int family, int type, int protocol);
        
        int bind(const struct sockaddr *sockaddr, socklen_t addrlen);

        int connect();

        int send();

        int recv();

        /*
         * On success, these calls return the number of bytes sent.  On error, -1 is returned
         * */
        int sendto(const char* buf, size_t len, int flags,
                const struct sockaddr* dstAddr, socklen_t addrlen);

        /*
         * These  calls  return  the  number  of bytes received, or -1 if an error occurred.
         * */
        int recvfrom(char* buf, size_t len, int flags,
                struct sockaddr* srcAddr, socklen_t* addrlen);

        int listen();

        int accept();

        int shutdown();
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

        int _shmid;          // shared memory identifier
        SharedBlock *_pBlock;// shared block
        int _protoPid;          // protocol process id

        int _socketId;          // might use process id
        int _family;
        int _type;
        int _protocol;
};

