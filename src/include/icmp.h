
#ifndef ICMP_H_
#define ICMP_H_

typedef struct sniff_icmp {
    uint8_t icmp_type;          // type of message
    uint8_t icmp_code;          // type sub code
    uint16_t icmp_sum;          // one complement check sum of struct 
    union {
        uint8_t ih_pptr;        // parameter problem pointer
        struct in_addr ih_gwaddr;   // Gateway Internet Address
        struct ih_idseque {
            uint16_t icd_id;    // identifier
            uint16_t icd_seq;   // sequence number
        } ih_idseque ;
        uint32_t ih_void;
    } icmp_hun ;
#define icmp_pptr_t           icmp_hun.ih_pptr
#define icmp_gwaddr_t         icmp_hun.ih_gwaddr
#define icmp_id_t             icmp_hun.ih_idseque.icd_id
#define icmp_seq_t            icmp_hun.ih_idseque.icd_seq
#define icmp_void_t           icmp_hun.ih_void
    union {
        struct id_ts {
            uint32_t its_otime; // Originate timestamp
            uint32_t its_rtime; // Receive timestamp
            uint32_t its_ttime; // Transmit timestamp
        } id_ts;
        struct id_ip {          
            struct sniff_ip idi_ip;
            /*options and then 64bits of data*/
        } id_ip;
        uint32_t id_mask;
        uint8_t id_data[1];
    } icmp_dun ;
#define icmp_otime_t          icmp_dun.id_ts.its_otime
#define icmp_rtime_t          icmp_dun.id_ts.its_rtime
#define icmp_ttime_t          icmp_dun.id_ts.its_ttime
#define icmp_ip_t             icmp_dun.id_ip.idi_ip
#define icmp_mask_t           icmp_dun.id_mask
#define icmp_data_t           icmp_dun.id_data
} icmphdr_t ;

#endif  // ICMP_H_

