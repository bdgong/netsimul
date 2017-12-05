#pragma once
//#ifndef IP_ARP_H_
//#define IP_ARP_H_

#include <sys/types.h>

const u_int8_t cARPHeaderLen = 28;

/*ARP header*/
struct sniff_arp {
    u_int16_t htype;        // Hardware Type
    u_int16_t ptype;        // Protocol Type
    u_int8_t hlen;          // Hardware Address Length
    u_int8_t plen;          // Protocol Address Length
    u_int16_t oper;         // Operation Code
    u_int8_t sha[6];        // Sender hardware address
    u_int32_t spa;          // Sender IP address
    u_int8_t tha[6];        // Target hardware address
    u_int32_t tpa;          // Target IP address
} __attribute__((packed));

typedef struct sniff_arp ARPHdr;

//#endif  // IP_ARP_H_
