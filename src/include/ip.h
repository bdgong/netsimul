#ifndef IP_H_
#define IP_H_

#include <netinet/in.h>
#include <netinet/ip.h>

/* to remove option, just set to 0 */
#define SIZE_OPTION 4
#define SIZE_IP (SIZE_OPTION+20)
#define SIZE_IP_HL (SIZE_IP/4)

const int cIPOptionValue = 0xFF020000; 

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,
                        ip_dst;         /* source and dest address */ 
        u_int   ip_opt;                 /* option value */

        bool isFragment() {
            return (ip_off & htons(IP_MF | IP_OFFMASK)) != 0;
        }

};

typedef struct sniff_ip iphdr_t;

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

#endif  // IP_H_

