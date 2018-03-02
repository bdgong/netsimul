#include "SharedBlock.h"
#include <map>

class CProtoSocket
{
    public:
        CProtoSocket();
        ~CProtoSocket();
        void run();
        // 
    private:
        // 
        CProtoSocket(const CProtoSocket&);
        CProtoSocket & operator=(const CProtoSocket&);

        void init();

        /*
         * Create and detach shared memory
         * */
        void createSharedMem();
        void destroySharedMem();

        void handleSockRequest();

        void handleCreate(SockPacket *sockPkt);
        void handleSendTo(SockPacket *sockPkt);

        int _shmid;          // shared memory identifier
        SharedBlock *_pBlock;// shared block

        std::map<int, Sock> _sockPool;

};

