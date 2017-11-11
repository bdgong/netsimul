
#ifndef UDP_H_
#define UDP_H_

#include <netinet/ip.h>

#define SIZE_UDP 8

#define SIZE_PSEUDO_UDP 12

// udp header
typedef struct sniff_udp {
    uint16_t uh_sport;          // source port
    uint16_t uh_dport;          // destination port
    uint16_t uh_len;            // udp length
    uint16_t uh_sum;            // udp checksum
} udphdr_t ;

//pseudo udp header for calculation of check sum
typedef struct pseudo_udp {
    struct in_addr saddr;       // source address
    struct in_addr daddr;       // destination address
    uint8_t zero;               // zero
    uint8_t protocol;           // protocol
    uint16_t len;               // UDP length
} pseudo_udp_t ;

#endif  // UDP_H_

