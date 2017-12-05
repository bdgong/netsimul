#include "Hardware.h"

/*network*/
#include <arpa/inet.h>
#include <linux/netdevice.h>
#include <cstring>

#include <algorithm>

#include "Util.h"

void CHardware::init()
{
    if(_isInited) 
        return;

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&_foundDevs, errbuf) == -1) {          // cal pcap findalldevs
        error("Couldn't find any device: %s\n", errbuf);
        return;
    }

    pcap_if_t *pDev = _foundDevs;
    while (pDev != NULL) {
        bpf_u_int32 flag = pDev->flags;

#ifdef DEBUG
        static bool t = true;
        if(t) {
            debug("Detected device: %s", pDev->name);
            t = false;
        }
        else
            log(" %s", pDev->name);
#endif 

        // find running and not loopback device
        if ((flag & PCAP_IF_RUNNING) && !(flag & PCAP_IF_LOOPBACK)) {
            Device dev;
            dev.name = pDev->name; 

            int progress = 0;

            // address
            pcap_addr_t *paddr = pDev->addresses;
            while (paddr != NULL) {
                struct sockaddr *sa = paddr->addr;
                
                if (sa->sa_family == AF_PACKET) {           // find hardware address
                    struct sockaddr_ll *sall = (struct sockaddr_ll *) sa;
                    memcpy(&(dev.hAddr), &(sall->sll_addr), ETH_ALEN); 
                    progress |= 0x01;
                }
                else if (sa->sa_family == AF_INET) {        // find ip address
                    struct sockaddr_in *sai = (struct sockaddr_in *) sa;
                    memcpy(&(dev.ipAddr), &(sai->sin_addr), sizeof(struct in_addr));
                    progress |= 0x10;
                }
                else {}

                if( (progress & 0x01) && (progress & 0x10) )// we only find mac & ip address
                    break;

                paddr = paddr->next;
            }

            _devs.push_back(dev);           // save to cache
        }
        else {}

        pDev = pDev->next;
    }

    log("\n");
    
    if (_devs.size() <= 0) {                        // make sure we get at least one device
        error("No suitable device found.\n");
        return ;
    }

    _defaultDev = &_devs.front();                   // open the first device as default handler
    _defaultDev->handler = pcap_open_live (_defaultDev->name, SNAP_LEN, 1, 1000, errbuf);
    if (_defaultDev->handler == NULL) {
        error("Couldn't open device %s : %s\n", _defaultDev->name, errbuf); 
        return ;
    }

    if (pcap_datalink(_defaultDev->handler) != DLT_EN10MB) { // make sure we're capturing on an Ethernet device
        error("%s is not an Ethernet device\n", _devs.front().name);
        return ;
    }

    _link = CLink::instance();
    _isInited = true;
#ifdef DEBUG
    debug("Hardware inited:\n");
    for (const Device& dev : _devs) {
        if(dev.name == _defaultDev->name) {         // use == because we use pointer for default device
            log("* (default) ");
        }
        dev.show();
    }
#endif 
}

void CHardware::transmit(packet_t *packet)
{
    if(_defaultDev == nullptr || _defaultDev->handler == nullptr) {
        error("Default device not avaliable.");
        return ;
    }

    unsigned char *buf = packet->buf;
    size_t size = packet->size;

    int byteSend = pcap_inject(_defaultDev->handler, buf, size);
    if(byteSend == -1) {
        error("Send packet failed.");
    }
    else {
        debug("Transmited packet to network (%d bytes).\n", byteSend);
    }
    //delete packet->buf;
    
}

