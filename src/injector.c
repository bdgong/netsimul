
/*
 * The injector take user input as a datagram inject to network.
 * */

#define APP_NAME		"injector"
#define APP_DESC		"Injector example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2017 BiDong Gong"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "include/ether.h"
#include "include/arp.h"
#include "include/ip.h"
#include "include/tcp.h"
#include "include/udp.h"
#include "include/netsimul.h"

#define SIZE_SEND_BUFFER 4096

void handle_user_input(pcap_t * handler);

void handle_inject(pcap_t *handler, const char * sendbuf, size_t size, char oper);

void encap_tcp(pcap_t *handler, const char * sendbuf, size_t size);

void encap_udp(pcap_t *handler, const char * sendbuf, size_t size);

void encap_ip();

void encap_ether();

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

int send_packet(pcap_t *handler, const u_char *buf, size_t size)
{

    // 
    return pcap_inject(handler, buf, size);

}

void encap_tcp(pcap_t *handler, const char * sendbuf, size_t size)
{

    int bytes_send;

    bytes_send = send_packet(handler, sendbuf, size);
    if(bytes_send == -1) {
        fprintf(stderr, "Send packet failed");
    }
    else {
        printf("Injected packet to network (%d bytes).", bytes_send);
    }

}

void encap_udp(pcap_t *handler, const char * sendbuf, size_t size)
{

    // 

}

void handle_inject(pcap_t *handler, const char * sendbuf, size_t size, char oper)
{

    if(oper == 't' || oper == 'T') {
        printf("\nInject with TCP...\n");
        encap_tcp(handler, sendbuf, size);
    }
    else {
        printf("\nInject with UDP...\n");
        encap_udp(handler, sendbuf, size);
    }

}

void handle_user_input(pcap_t * handler)
{

    char sendbuf[SIZE_SEND_BUFFER], ch;
    int count;

    printf("\nEnter message to inject (ends with an empty line):\n"); 
    count = 0;
    while(1) {
        ch = getchar();
        if(count < SIZE_SEND_BUFFER) {
            sendbuf[count] = ch;
        }
        else {
            printf("\n--maximum characters meeted (%d), end of input--\n", SIZE_SEND_BUFFER);
            break;
        }

        if(count > 0 && ch == '\n' && sendbuf[count-1] == '\n') {
            break;
        }
        ++count;
    }
    sendbuf[count] = '\0';

    printf("**MESSAGE TO SEND**\n\n%s\n\n", sendbuf);

    printf("Inject with TCP or UDP? [T/U]: "); 
    ch = getchar(); CLEAR();
    while (!(ch == 't' || ch == 'T' || ch == 'u' || ch == 'U')) {
        printf("Please enter T(t) or U(u): ");
        ch = getchar(); CLEAR();
    }

    handle_inject(handler, sendbuf, count, ch);

}

int main(int argc, char** argv) {
    char *dev = NULL;                           // capture device name
    char errbuf[PCAP_ERRBUF_SIZE];              // error buffer
    pcap_t *handler;                             // packet capture handle

    bpf_u_int32 mask;                           // subnet mask
    bpf_u_int32 net;                            // ip
    struct in_addr addr_net, addr_mask;

    print_app_banner();

    /* get device name */
    if(argc == 2) {
        dev = argv[1];
    }
    else {
        dev = pcap_lookupdev(errbuf);
        if(dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    else {
        addr_net.s_addr = net;
        addr_mask.s_addr = mask;
        printf("IP: %s\n", inet_ntoa(addr_net));
        printf("Netmask: %s\n", inet_ntoa(addr_mask));
    }

    /*open inject device*/
    handler = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if(handler == NULL) {
        fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /*make sure we're capturing on an Ethernet device*/
    if (pcap_datalink(handler) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /*handle user's input*/
    handle_user_input(handler);

    /*cleanup*/
    pcap_close(handler);

    printf("\nInject complete.\n");

    return 0;
}

