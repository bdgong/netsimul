
#ifndef ETHER_H_
#define ETHER_H_

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN	6
#endif

/*MAC address in ASCII format length*/
#define MAC_ASCII_LEN 18

/*
 * Ethernet Type Defines, see /usr/include/net/ethernet.h
 * */

/*#define ETHER_T_IPv4    0x0800      // Internet Protocol Version 4*/
/*#define ETHER_T_IPv6    0x86DD      // Internet Protocol Version 6*/
/*#define ETHER_T_ARP     0x0806      // Address Resolution Protocol */
/*#define ETHER_T_RARP    0x8035      // Reverse Address Resolution Protocol */
/*#define ETHER_T_ETHERTALK   0x809B  // AppleTalk over Ethernet*/
/*#define ETHER_T_PPP     0x880B      // Point-to-Point Protocol*/
/*#define ETHER_T_PPPoEDS     0x8863  // PPPoE Discovery Stage*/
/*#define ETHER_T_PPPoESS     0x8864  // PPPoE Session Stage*/
/*#define ETHER_T_SNMP    0x814C      // Simple Network Management Protocol*/

/* Ethernet header */
typedef struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
} ethernethdr_t ;

#endif  // ETHER_H_

