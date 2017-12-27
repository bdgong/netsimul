
/*
 * The injector take user input as a datagram inject to network.
 * */

#define APP_NAME		"injector"
#define APP_DESC		"Injector example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2017 BiDong Gong (Antonio)"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <linux/netdevice.h>
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "netsimul.h"

#include "Network.h"
#include "Link.h"
//#include "Hardware.h"

#define SIZE_SEND_BUFFER 4096
#define SIZE_IP_ADDR_STR 16
#define SIZE_PORT_STR 5

#define FRAGMENT_TEST 1

const char poem[] = {
        "The farthest distance in the world\n"\
        "Is not the distance between life and death\n"\
        "But you don't know I love you when I stand in front of you\n"\
        "The farthest distance in the world\n"\
        "Is not you don't know I love when I stand in front of you\n"\
        "But I cannot say I love you when I love you so madly\n"\
        "The farthest distance in the world\n"\
        "Is not I cannot say I love you when I love you so madly\n"\
        "But I can only bury it in my heart dispite the unbearable yearing\n"\
        "The farthest distance in the world\n"\
        "Is not I can only bury it in my heart dispite the unbearable yearning\n"\
        "But we cannot be together when we love each other\n"\
        "The farthest distance in the world\n"\
        "Is not we cannot be together when we love each other\n"\
        "But we pretend caring nothing even we know love is unconquerable\n"\
        "The farthest distance in the world\n"\
        "Is not the distance between two trees\n"\
        "But the branches cannot depend on each other in wind even they grow from the same root\n"\
        "The farthest distance in the world\n"\
        "Is not the branches cannot depend on each other\n"\
        "But two stars cannot meet even they watch each other\n"\
        "The farthest distance in the world\n"\
        "Is not the track between two stars\n"\
        "But nowhere to search in a tick after two tracks join\n"\
        "The farthest distance in the world\n"\
        "Is not nowhere to search in a tick\n"\
        "But doomed not to be together before they meet\n"\
        "The farthest distance in the world\n"\
        "Is the distance between fish and bird\n"\
        "One is in the sky, another is in the sea\n"\
        "\n"\
        "The farthest distance in the world\n"\
        "Is the distance between fish and bird\n"\
        "One is in the sky, another is in the sea\n"\
        "\n"\
        "The farthest distance in the world\n"\
        "Is the distance between fish and bird\n"\
        "One is in the sky, another is in the sea\n"
};

void handle_user_input(pcap_t * handler);

void handle_inject(pcap_t *handler, packet_t *packet);

void encap_tcp(pcap_t *handler, packet_t *packet);

void encap_udp(pcap_t *handler, packet_t *packet);

void encap_ip(pcap_t *handler, packet_t *packet);

void encap_ether(pcap_t *handler, packet_t *packet);

int send_packet(pcap_t *handler, const u_char *buf, size_t size);

/*
 * app name/banner
 */
void print_app_banner()
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

}

/*
 * Send out packet to network
 *
 * @handler     A pcap_t handler use to inject packet to network
 * @buf         The packet to send
 * @size        The packet size
 * */
int send_packet(pcap_t *handler, const u_char *buf, size_t size)
{

    int bytes_send;

    bytes_send = pcap_inject(handler, buf, size);
    if(bytes_send == -1) {
        fprintf(stderr, "Send packet failed.");
    }
    else {
        printf("Injected packet to network (%d bytes).\n", bytes_send);
    }

    return bytes_send;

}

void encap_tcp(pcap_t *handler, packet_t *packet)
{

    send_packet(handler, packet->buf, packet->size);
    /*int bytes_send;                                                  */

    /*bytes_send = send_packet(handler, packet->buf, packet->size);    */
    /*if(bytes_send == -1) {                                           */
    /*    fprintf(stderr, "Send packet failed");                       */
    /*}                                                                */
    /*else {                                                           */
    /*    printf("Injected packet to network (%d bytes).", bytes_send);*/
    /*}                                                                */

}

uint16_t cksum(const u_char *const buf, size_t size)
{
    uint32_t sum;
    uint16_t *p = (uint16_t *)buf;

    sum = 0;
    while(size > 1) {
        sum += *p++;
        size -= 2;
    }

    // padding as needed
    if(size == 1) {
        sum += *((u_char *)p);
    }

    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)((~sum) & 0xFFFF);
}

uint16_t cksum_udp(const udphdr_t *const udp, const packet_t *const packet)
{

    uint16_t sum;
    u_char *buf;
    size_t size;

    pseudo_udp_t pseudo_udp;

    pseudo_udp.saddr    = packet->saddr;
    pseudo_udp.daddr    = packet->daddr;
    pseudo_udp.zero     = 0;
    pseudo_udp.protocol = IPPROTO_UDP;
    pseudo_udp.len      = udp->uh_len;

    size = SIZE_PSEUDO_UDP + SIZE_UDP + packet->size;
    buf = (u_char *)malloc(size);
    memcpy(buf, &pseudo_udp, SIZE_PSEUDO_UDP);
    memcpy(buf+SIZE_PSEUDO_UDP, udp, SIZE_UDP);
    memcpy(buf+SIZE_PSEUDO_UDP+SIZE_UDP, packet->buf, packet->size);

    sum = cksum(buf, size);

    free(buf);

    return sum;

}

void encap_udp(pcap_t *handler, packet_t *packet)
{

    udphdr_t udp; 

    u_char *buf;
    size_t size_new;

    size_new = SIZE_UDP + packet->size;

    /*create UDP header*/
    udp.uh_sport    = htons(packet->sport);
    udp.uh_dport    = htons(packet->dport);
    udp.uh_len      = htons(size_new);
    udp.uh_sum      = 0;

    udp.uh_sum      = cksum_udp(&udp, packet);

    /*add UDP header*/
    buf = (u_char*)malloc(size_new);            // to be free() [1]
    memcpy(buf, &udp, SIZE_UDP);
    memcpy(buf+SIZE_UDP, packet->buf, packet->size);
    packet->buf     = buf;
    packet->size    = size_new;

    encap_ip(handler, packet);

}

void encap_udp2(pcap_t *handler, packet_t *packet)
{

    // make a copy of original data
    int sizeUDPHdr = 8;         // size in bytes
    int sizeIPHdr = 20;
    int sizeEtherHdr = 14;
    int sizeHdr = sizeUDPHdr + sizeIPHdr + sizeEtherHdr;

    // allocate more space include header
    packet_t pkt(sizeHdr + packet->size);
    pkt.copyMetadata(*packet);

    pkt.proto = IPPROTO_UDP;

    // reserve space for header
    pkt.reserve(sizeHdr);

    // copy payload
    pkt.put(packet->size);
    memcpy(pkt.data, packet->buf, packet->size);

    // prepare UDP header
    udphdr_t udp; 
    size_t size_new = SIZE_UDP + packet->size;

    udp.uh_sport    = htons(packet->sport);
    udp.uh_dport    = htons(packet->dport);
    udp.uh_len      = htons(size_new);
    udp.uh_sum      = 0;

    udp.uh_sum      = cksum_udp(&udp, packet);

    // push UDP header space
    pkt.push(SIZE_UDP);

    // copy UDP header
    memcpy(pkt.data, &udp, SIZE_UDP);

    // call network to do next work
    CNetwork *network = CNetwork::instance();
    network->send(&pkt);

}

uint16_t cksum_ip(const iphdr_t * const ip)
{

    return cksum((u_char *)ip, SIZE_IP);

}

void encap_ip(pcap_t *handler, packet_t *packet)
{

    iphdr_t ip;

    u_char *buf;
    size_t size_new;

    size_new = SIZE_IP + packet->size;

    /*create IP header*/
    ip.ip_vhl   = 0x45;
    ip.ip_tos   = 0;
    ip.ip_len   = htons(size_new);
    ip.ip_id    = htons(0xF96D);
    ip.ip_off   = htons(IP_DF);     // don't fragment
    ip.ip_ttl   = IPDEFTTL;         // default TTL
    ip.ip_p     = INJECT_OP_TCP(packet) ? IPPROTO_TCP : IPPROTO_UDP;
    ip.ip_sum   = 0;
    ip.ip_src   = packet->saddr;
    ip.ip_dst   = packet->daddr;

    ip.ip_sum   = cksum_ip(&ip);

    /*printf("Debug - header length: %d\n", IP_HL(&ip));                    */
    /*printf("Debug - total length: %d(%d)\n", ip.ip_len, ntohs(ip.ip_len));*/
    /*printf("Debug - protocol: %d\n", ip.ip_p);                            */
    /*printf("Debug - src: %s\n", inet_ntoa(ip.ip_src));                    */
    /*printf("Debug - dst: %s\n", inet_ntoa(ip.ip_dst));                    */

    /*add IP header*/
    buf = (u_char*)malloc(size_new);
    memcpy(buf, &ip, SIZE_IP);
    memcpy(buf+SIZE_IP, packet->buf, packet->size);
    free(packet->buf);          // do free() [1]
    packet->buf     = buf;      // to be free() [2]
    packet->size    = size_new;

    packet->ept     = ETH_P_IP;

    //encap_ether(handler, packet);

    //CNetwork *network = CNetwork::instance();
    //network->send(packet);
    //CLink *link = CLink::instance();
    //link->send(packet);

    delete packet->buf;         // do free() [2]

}

void encap_ether(pcap_t *handler, packet_t *packet)
{
    
    ethernethdr_t ether;

    struct ether_addr *shost, *dhost;

    const char *default_shost = "08:00:27:a8:01:cc";  // 192.168.0.5
    const char *default_dhost = "08:00:27:05:6e:fb";  // 192.168.0.3

    u_char *buf;
    size_t size_new;
    uint32_t fcs;                   // frame check sequence

    /*create Ethernet header*/
    ether.ether_type = htons(ETHERTYPE_IP);

    //shost = ether_aton(default_shost);
    shost = ether_aton(default_shost);
    memcpy(ether.ether_shost, shost, ETHER_ADDR_LEN);
    //dhost = ether_aton(default_dhost);
    dhost = ether_aton(default_dhost);
    memcpy(ether.ether_dhost, dhost, ETHER_ADDR_LEN);

    /*add Ethernet header*/
    size_new = SIZE_ETHERNET + packet->size + SIZE_ETHER_SUM;
    buf = (u_char*)malloc(size_new);
    memset(buf, 0, size_new);
    memcpy(buf, &ether, SIZE_ETHERNET);
    memcpy(buf+SIZE_ETHERNET, packet->buf, packet->size);
    fcs = 0;
    memcpy(buf+SIZE_ETHERNET+packet->size, &fcs, SIZE_ETHER_SUM);

    free(packet->buf);          // do free() [2]
    packet->buf     = buf;      // to be free() [3]
    packet->size    = size_new;

    //CHardware *hardware = CHardware::instance();
    //hardware->transmit(packet);
    //send_packet(handler, buf, size_new); 

    free(packet->buf);          // do free() [3]

}

void handle_inject(pcap_t *handler, packet_t *packet)
{

    if(INJECT_OP_TCP(packet)) {
        printf("\nInject with TCP...\n");
        encap_tcp(handler, packet);
    }
    else {
        printf("\nInject with UDP2...\n");
        encap_udp2(handler, packet);
    }

}

void handle_user_input(pcap_t * handler)
{

    packet_t packet;                    // inject packet 
    char buf[SIZE_SEND_BUFFER], ch;     // temporary input buffer
    int count;                          // inject message character count
    char saddr[16], daddr[16];          // source & destination ip address
    uint16_t sport, dport;              // source & destination port
    char tmpstr[16];

    const char *default_saddr = "192.168.0.5";
    default_saddr = inet_ntoa( CLink::instance()->getDefaultDevice()->ipAddr );
    //const char *default_daddr = "192.168.0.3";
    const char *default_daddr = "211.67.27.254";
    uint16_t default_sport = 1314;
    uint16_t default_dport = 1618;

#if FRAGMENT_TEST==1

    printf("\nUsed test string, length=%ld\n\n", sizeof(poem));

    packet.buf = (unsigned char*)poem;
    packet.size = sizeof(poem);

#else

    /*Enter inject message */
    printf("\nEnter message to inject (ends with an empty line):\n"); 
    count = 0;
    while(1) {
        ch = getchar();
        if(count < SIZE_SEND_BUFFER) {
            buf[count] = ch;
        }
        else {
            printf("\n--maximum characters meeted (%d), end of input--\n", SIZE_SEND_BUFFER);
            break;
        }

        if(count > 0 && ch == '\n' && buf[count-1] == '\n') {
            break;
        }
        ++count;
    }
    buf[count] = '\0';
    packet.buf = (u_char *)buf;
    packet.size = count;

#endif

    printf("**MESSAGE TO SEND**\n\n%s\n\n", packet.buf);

    /*Determine inject protocol*/
    printf("Inject with TCP or UDP? [T/U]: "); 
    ch = getchar(); CLEAR();
    while (!(ch == 't' || ch == 'T' || ch == 'u' || ch == 'U')) {
        printf("Please enter T(t) or U(u): ");
        ch = getchar(); CLEAR();
    }
    packet.oper = ch;

    /*Determine inject source & destination*/
    printf("Sender ip address (default %s, use it just press <enter>): ", default_saddr);
    ch = getchar();
    if(ch == '\n') {
        strncpy(saddr, default_saddr, SIZE_IP_ADDR_STR);    
    }
    else {
        saddr[0] = ch;
        fgets(saddr+1, SIZE_IP_ADDR_STR, stdin);
        saddr[strlen(saddr)-1] = '\0';          // eliminate the newline character
    }

    printf("Sender port (default %d, use it just press <enter>): ", default_sport);
    ch = getchar();
    if(ch == '\n') {
        sport = default_sport;  
    }
    else {
        tmpstr[0] = ch;
        fgets(tmpstr+1, SIZE_PORT_STR, stdin);
        sport = atoi(tmpstr);
    }

    printf("Destination ip address (default %s, use it just press <enter>): ", default_daddr);
    ch = getchar();
    if(ch == '\n') {
        strncpy(daddr, default_daddr, SIZE_IP_ADDR_STR);    
    }
    else {
        daddr[0] = ch;
        fgets(daddr+1, SIZE_IP_ADDR_STR, stdin);
        daddr[strlen(daddr)-1] = '\0';          // eliminate the newline character
    }

    printf("Destination port (default %d, use it just press <enter>): ", default_dport);
    ch = getchar();
    if(ch == '\n') {
        dport = default_dport;  
    }
    else {
        tmpstr[0] = ch;
        fgets(tmpstr+1, SIZE_PORT_STR, stdin);
        dport = atoi(tmpstr);
    }

    if( inet_aton(saddr, &packet.saddr) == 0) {
        fprintf(stderr, "Invalid source address: %s\n", saddr); 
        exit(EXIT_FAILURE);
    }
    if( inet_aton(daddr, &packet.daddr) == 0) {
        fprintf(stderr, "Invalid destination address: %s\n", daddr); 
        exit(EXIT_FAILURE);
    }
    packet.sport = sport;
    packet.dport = dport;

    printf("\n%s:%d > %s:%d\n", saddr, packet.sport, daddr, packet.dport);

    handle_inject(handler, &packet);

}

int main(int argc, char** argv) {
    //CHardware * hardware = CHardware::instance();
    //hardware->init();
    //CLink *link = CLink::instance();
    //link->init();
    CNetwork::instance()->init();

    int k = 2;
    while (k-- > 0) {
        handle_user_input(nullptr);

        sleep(2);
    }

    return 0;
}

