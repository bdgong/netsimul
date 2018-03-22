#ifndef TCP_H_
#define TCP_H_

#include <sys/types.h>

#define SIZE_TCP 20

/*
 * TCP Maximum Segment Size (MTU - SIZE_TCP - SIZE_IP)
 * */
const int cTCPMSS = 1456;

/* TCP header */
typedef u_int tcp_seq;

typedef struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
} tcphdr_t ;

/*
 * TCP control buffer
 * */
typedef struct tagTCPCB {
    // ...
    u_int seq;          // start sequence of buffer 
    u_int endSeq;       // end sequence of buffer
    u_int ack;          // acked number
} TCPCB;

#define TCP_PKT_CB(__packet) ((TCPCB *)&(__packet)->cb[0])

#endif  // TCP_H_

