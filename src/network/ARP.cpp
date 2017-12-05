#include "arp.h"

#include "Util.h"

#include <cstring>
#include <utility>

void CARP::init()
{
    if (_isInited)
        return;

    _link       = CLink::instance();

    _isInited   = true;
    debug("ARP initied.\n");

}

CARP::~CARP()
{
    // delete allocated space if there is pending packet
    for (auto &pair : _arpQueue) {
        auto & list = pair.second;
        for (auto &item : list) {
            delete item.packet.buf;
            item.packet.buf = nullptr;
        }
    }
}

void CARP::sendDatagram(packet_t *packet)
{
    const Device *dev = _link->getDefaultDevice();
    if (dev == nullptr) {
        error("<ARP> Cannot get avaliable device.");
        return;
    }

    const struct in_addr & daddr = packet->daddr;

    packet->sha = dev->hAddr;       // set local hardware address

    if (_arpTable.count(daddr.s_addr) == 1) {   // check cache: find
        debug("Hit cache for: %s\n", inet_ntoa(daddr));

        const ARPTableItem & cache = _arpTable.at(daddr.s_addr);
        packet->dha = cache.mac;

        _link->transmit(packet);    // call link layer transmit
    }
    else {                                      // need send ARP packet
        debug("No cache for: %s, send ARP.\n", inet_ntoa(daddr));

        int cachedBefore = cache(daddr, packet);    // cache packet for later transmisson
        
        if (cachedBefore == 0) {                    // address resolve if no previous request send
            memcpy(&packet->dha, ether_aton("FF:FF:FF:FF:FF:FF"), ETH_ALEN);
        
            sendARP(daddr, packet);
        } else {}
    }

}

int CARP::cache(const struct in_addr &key, packet_t *packet)
{
    packet_t copy = *packet;
    copy.buf = new u_char[packet->size];
    memcpy(&copy.buf, packet->buf, packet->size);

    std::list<ARPQueueItem> & kList = _arpQueue[key.s_addr];
    ARPQueueItem item{
        .packet = std::move(copy)           // save copy time by move
    };
    kList.push_back(item);

    return kList.size() - 1;

}

void CARP::sendARP(const struct in_addr &addr, packet_t *packet)
{
    ARPHdr arp;
    arp.htype   = htons(ARPHRD_ETHER);          // linux/if_arp.h
    arp.ptype   = htons(ETH_P_IP);              // linux/if_ether.h
    arp.hlen    = ETH_ALEN;
    arp.plen    = 4;
    arp.oper    = htons(ARPOP_REQUEST);
    memcpy(&arp.sha, &packet->sha, ETH_ALEN);
    arp.spa     = packet->saddr.s_addr;
    memset(&arp.tha, 0, ETH_ALEN);
    arp.tpa     = addr.s_addr;

    packet_t pkt = *packet;
    pkt.arphdr  = arp;
    pkt.ept     = ETH_P_ARP;

    _link->transmit(&pkt);

}

