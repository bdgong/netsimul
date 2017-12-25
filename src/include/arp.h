#pragma once
//#ifndef ARP_H_
//#define ARP_H_

#include "packet.h"
#include "Link.h"

#include <sys/types.h>
#include <map>
#include <list>
#include <string>

using std::map;
using std::list;

const uint16_t cARPMaxTTL = 500;

/*
 * ARPPacket - ARP packet 
 * */
typedef struct arp_packet {
    ether_header etherhdr;
    ARPHdr arp;
} ARPPacket;

/*
 * struct ARPTableItem - Cache avaliable neighbors
 * */
typedef struct arp_table_item { 
    in_addr_t ip;
    struct ether_addr mac;
    u_int16_t ttl;
} ARPTableItem; 

typedef std::map<in_addr_t, ARPTableItem> ARPTable; 

/*
 * struct ARPQueueItem - Cache pending datagrams
 * */
typedef struct arp_queue_item { 
    packet_t *packet;
} ARPQueueItem;

typedef std::map<in_addr_t, std::list<ARPQueueItem> > ARPQueue;

class CLink;
class CHardware;

class CARP 
{
public:
    static CARP * instance() 
    {
        static CARP inst;
        return &inst;
    }

    void init();

    ~CARP();

    /*
     * Send out network layer datagram 
     * */
    void sendDatagram(packet_t *packet);

    /*
     * Send out ARP packet
     * */
    void sendARP(const struct in_addr &addr, packet_t *packet);

    /*
     * Received ARP packet
     * */
    void recvARP(packet_t *packet);

private:
    bool _isInited;

    ARPTable _arpTable;          // arp table cache - Neighbors
    ARPQueue _arpQueue;          // arp queue - Pending datagrams wait for ARP resolve

    CLink *_link;

    /*
     * Cache packet to queue with key.  
     *
     * @return The item number has been cached with key.
     * */
    int cache(const struct in_addr &key, packet_t *packet);

    /*
     * Cache ARP item to table.
     * */
    void cache(const ARPHdr *arphdr);

    /*
     * Process cached datagrams when arp reply received
     *
     * @addr The address resolved
     * */
    void processPendingDatagrams(in_addr_t addr);

    void replyARP(const ARPHdr *arphdr);

    CARP() : _isInited(false), _link(nullptr)
    {
    }

};

//#endif  // ARP_H_
