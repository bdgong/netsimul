
#ifndef ARP_H_
#define ARP_H_

#include <sys/types.h>
#include <map>
#include <list>
#include <string>

using std::map;
using std::list;

/*ARP header*/
typedef struct sniff_arp {
    u_int16_t htype;        // Hardware Type
    u_int16_t ptype;        // Protocol Type
    u_int8_t hlen;          // Hardware Address Length
    u_int8_t plen;          // Protocol Address Length
    u_int16_t oper;         // Operation Code
    u_int8_t sha[6];        // Sender hardware address
    u_int8_t spa[4];        // Sender IP address
    u_int8_t tha[6];        // Target hardware address
    u_int8_t tpa[4];        // Target IP address
} arphdr_t;

/*
 * struct ARPTableItem - Cache avaliable neighbors
 * */
typedef struct arp_table_item { 
    // 
} ARPTableItem; 
typedef std::map<std::string, ARPTableItem> ARPTable;

/*
 * struct ARPQueueItem - Cache pending datagrams
 * */
typedef struct arp_queue_item { 
} ARPQueueItem;
typedef std::map<std::string, std::list<ARPQueueItem> > ARPQueue;

class CARP 
{
public:
    CARP()
    {
    }

    ~CARP() 
    {
    }

    /*
     * Send out network layer datagram 
     * */
    void sendDatagram();

    /*
     * Send out ARP packet
     * */
    void sendARP();

    /*
     * Received ARP packet
     * */
    void recvARP();

private:
    ARPTable _arpTable;          // arp table cache - Neighbors
    ARPQueue _arpQueue;          // arp queue - Pending datagrams wait for ARP resolve

};

#endif  // ARP_H_

