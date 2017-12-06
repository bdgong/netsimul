#include "arp.h"

#include "Util.h"

#include <cstring>
#include <utility>
#include <algorithm>

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
    memmove(copy.buf, packet->buf, packet->size);   // in case overlap, use memmove instead

    std::list<ARPQueueItem> & kList = _arpQueue[key.s_addr];
    ARPQueueItem item{
        .packet = std::move(copy)               // save copy time by move
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

void CARP::recvARP(packet_t *packet)
{
    debug("<ARP> received.\n");

    ARPHdr *arphdr = (ARPHdr *)packet->rcvbuf;

    if (ntohs(arphdr->htype) == ARPHRD_ETHER && ntohs(arphdr->ptype) == ETH_P_IP) {
        u_int16_t oper = ntohs(arphdr->oper);

        struct in_addr spa, tpa;
        spa.s_addr = arphdr->spa;
        tpa.s_addr = arphdr->tpa;
        debug("Sender      IP: %s, MAC: %s\n", inet_ntoa(spa), ether_ntoa((struct ether_addr *)arphdr->sha));
        debug("Destination IP: %s, MAC: %s\n", inet_ntoa(tpa), ether_ntoa((struct ether_addr *)arphdr->tha));

        if (oper == ARPOP_REPLY) {
            debug("arp reply.  cache it.\n");
            ARPTableItem item;          
            item.ip     = arphdr->spa;
            memcpy(&item.mac, &arphdr->sha, ETH_ALEN);
            item.ttl    = cARPMaxTTL;

            _arpTable.emplace(item.ip, item);   // cache to arp table
            // can not call it here? why
            processPendingDatagrams(item.ip);   // notify for pending ip datagram
            //debug("processed pending datagrams with %s.\n", inet_ntoa(*(struct in_addr*)&item.ip));
        }
        else if(oper == ARPOP_REQUEST)  {
            debug("arp request\n");
        }
        else {
            debug("Unknown arp operation code: %d\n", oper);
        }
    }
    else {
        error("Invalid ARP packet.\n");
    }

}

void CARP::processPendingDatagrams(in_addr_t addr)
{
    ARPQueue::iterator it = _arpQueue.find(addr);
    if (it != _arpQueue.end()) {
        auto &itemList = it->second;

        for (auto &item : itemList) {
            _link->transmit(&item.packet);
            delete[] item.packet.buf;
            item.packet.size = 0;
            item.packet.buf = nullptr;
        }

        //for_each(itemList.begin(), itemList.end(), [=](ARPQueueItem &item) {
                //packet_t &pkt = item.packet;
                //_link->transmit(&pkt);
        //});

        _arpQueue.erase(it);
    }

}
