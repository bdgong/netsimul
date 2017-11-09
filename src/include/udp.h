
#ifndef UDP_H_
#define UDP_H_

typedef struct sniff_udp {
    uint16_t uh_sport;          // source port
    uint16_t uh_dport;          // destination port
    uint16_t uh_len;            // udp length
    uint16_t uh_sum;            // udp checksum
} udphdr_t ;

#endif  // UDP_H_

