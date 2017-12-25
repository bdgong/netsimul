#pragma once
//#ifndef PACKET_H_
//#define PACKET_H_

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <cstring>
#include <cstdio>           // use printf to see how many copy used

#include "ip_arp.h"

/*
 * Core structure used for networking, referece to Linux struct sk_buff design.
 * */
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
    //const u_char            *rcvbuf;// packet data receive buffer

    bool                    allocated;// True if this struct allocated by heap memory
    unsigned int            len;    // Length of the actual data

    unsigned char           *tail;  // Data tail
    unsigned char           *end;   // Buffer end
    unsigned char           *head,  // Buffer head
                            *data;  // Data pointer

    inject_packet() : size(0), len(0), allocated(false)
    {
        buf = head = tail = data = tail = nullptr;
        //rcvbuf = nullptr;
    }

    inject_packet(unsigned int size) : size(size), len(0), allocated(true)
    {
        buf = new unsigned char[size]{0};

        head = data = tail = buf;
        end = buf + size;
    }

    /*
     * Copy constructor.
     *
     * So, remember to use reference& in any where you can.
     * */
    inject_packet (const inject_packet &cp)
    {

        buf = new unsigned char[cp.size]{0};

        head = data = tail = buf;
        end = buf + cp.size;

        data = head + (cp.data - cp.head);
        tail = head + (cp.tail - cp.head);

        len     = cp.len;
        size    = cp.size;
        saddr   = cp.saddr;
        daddr   = cp.daddr;
        sha     = cp.sha;
        dha     = cp.dha;
        sport   = cp.sport;
        dport   = cp.dport;
        oper    = cp.oper;
        ept     = cp.ept;
        arphdr  = cp.arphdr;

        allocated = cp.allocated;

        memmove(buf, cp.buf, cp.size);

        printf("**Copied packet**\n");

    }

    ~inject_packet()
    {
        if (allocated && buf != nullptr) {
            delete [] buf;
            buf = nullptr;
            head = data = tail = end = buf;
            size = len = 0;
        }

    }

    /*
     * Reserve space of headroom.
     *
     * Increase the headroom of an empty &sk_buff by reducing the tail
     * room. This is only allowed for an empty buffer.
     * */
    void reserve(unsigned int length)
    {
        data += length;
        tail += length;
    }

    /*
     * Add data length to a buffer.
     *
     * Extends the used data area of the buffer.
     * */
    void put(unsigned int length)
    {
        tail += length;
        len += length;
    }

    /*
     * Add data to the start of a buffer.
     *
     * Extends the used data area of the buffer at the buffer start.
     * */
    void push(unsigned int length)
    {
        data -= length;
        len += length;
    }

    /*
     * Remove data from the start of a buffer.
     *
     * */
    void pull(unsigned int length)
    {
        data += length;
        len -= length;
    }


};

typedef struct inject_packet packet_t;
typedef struct inject_packet Packet;

//#endif // PACKET_H_
