/*
 * Simple ARP Sniffer.
 * To compile: g++ simple_arp_sniffer.cpp -o simple_arp_sniffer -lpcap
 * Run as root!
 * */

#include <pcap.h>
#include <netinet/in.h>
#include <cstdlib>
#include <cstring>

//ARP Header, (assuming Ethernet+IPv4)
#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct arphdr {
    u_int16_t htype;        // Hardware Type
    u_int16_t ptype;        // Protocol Type
    u_char hlen;            // Hardware Address Length
    u_char plen;            // Protocol Address Length
    u_int16_t oper;         // Operation Code
    u_char sha[6];          // Sender harder address
    u_char spa[4];          // Sender IP address
    u_char tha[6];          // Target harder address
    u_char tpa[4];          // Target IP address
} arphdr_t;

#define MAXBYTES2CAPTURE 2048

int main(int argc, char * argv[]) {
    int i = 0;

    bpf_u_int32 netaddr = 0, mask = 0;  // To store network address and netmask

    struct bpf_program filter;          // Place to store the BPF filter program

    char errbuf[PCAP_ERRBUF_SIZE];      // Error buffer

    pcap_t *descr = NULL;               // Network interface handler

    struct pcap_pkthdr pkthdr;          // Packet information(timestamp,size...)

    const unsigned char * packet = NULL;// Received raw data

    arphdr_t * arpheader = NULL;        // Pointer to the ARP header
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if(argc != 2) {
        printf("USAGE: simple_arp_sniffer <interface>\n");
        exit(1);
    }

    // Open network device for packet capture
    descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 0, -1, errbuf);
    //descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 0, 512, errbuf);
    
    // Look up info from the capture device.
    pcap_lookupnet(argv[1], &netaddr, &mask, errbuf);

    // Compiles the filter expression into a BPF filter program
    pcap_compile(descr, &filter, "arp", 1, mask);

    // Load the filter program into the packet capture 
    pcap_setfilter(descr, &filter);

    while(1) {
        // Get one packet
        packet = pcap_next(descr, &pkthdr);

        // Point to the ARP header
        arpheader = (struct arphdr *)(packet + 14);

        printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len);
        printf("Hardware type: %s\n", ((ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"));
        printf("Protocol type: %s\n", ((ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"));
        printf("Operation: %s\n", ((ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply"));

        //If is Ethernet and IPv4, print packet contents
        if( ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
            printf("Sender MAC: ");
            for(i=0; i<6 ; ++i)
                printf("%02X:", arpheader->sha[i]);
            printf("\nSender IP: ");
            for(i=0; i<4 ; ++i)
                printf("%d.", arpheader->spa[i]);
            printf("\nTarget MAC: ");
            for(i=0; i<6 ; ++i)
                printf("%02X:", arpheader->tha[i]);
            printf("\nTarget IP: ");
            for(i=0; i<4 ; ++i)
                printf("%d.", arpheader->tpa[i]);
            printf("\n");
        }
    }

    return 0;
}

