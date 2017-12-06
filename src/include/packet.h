#pragma once
//#ifndef PACKET_H_
//#define PACKET_H_

#include <arpa/inet.h>
#include <netinet/ether.h>

#include "ip_arp.h"

/*Inject packet options*/
struct inject_packet {
    u_char                  *buf;   // packet data send buffer
    size_t                  size;   // size of data bufer
    struct in_addr          saddr,  // source ip address
                            daddr;  // destination ip address
    struct ether_addr       sha,    // source hardware address
                            dha;    // destination hardware address
    uint16_t                sport,  // source port
                            dport;  // destination port
    u_char                  oper;   // operation code
    uint16_t                ept;    // ethernet packet type
    ARPHdr                  arphdr; // arp header 
#define INJECT_OP_TCP(p) (p->oper == 't' || p->oper == 'T')
#define INJECT_OP_UDP(p) (p->oper == 'u' || p->oper == 'U')
    const u_char            *rcvbuf;// packet data receive buffer

    inject_packet() {
        buf = nullptr;
        rcvbuf = nullptr;
        size = 0;
    }
};

typedef struct inject_packet packet_t;
typedef struct inject_packet Packet;

//#endif // PACKET_H_
