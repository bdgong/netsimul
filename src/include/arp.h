
#ifndef ARP_H_
#define ARP_H_

/*ARP header*/
typedef struct sniff_arp {
    u_int16_t htype;        // Hardware Type
    u_int16_t ptype;        // Protocol Type
    u_char hlen;            // Hardware Address Length
    u_char plen;            // Protocol Address Length
    u_int16_t oper;         // Operation Code
    u_char sha[6];          // Sender hardware address
    u_char spa[4];          // Sender IP address
    u_char tha[6];          // Target hardware address
    u_char tpa[4];          // Target IP address
} arphdr_t;

#endif  // ARP_H_

