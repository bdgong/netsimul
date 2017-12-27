#include "arp.h"
#include "ether.h"

#include "Util.h"

#include <cstring>
#include <utility>
#include <algorithm>

#define TAG "<ARP> "

void CARP::init()
{
    if (_isInited)
        return;

    _link       = CLink::instance();
    // Since the init() is called up to down order, ARP no need to call link's init() any more
    //_link->init();

    _isInited   = true;
    debug(DBG_DEFAULT, TAG "initied.");

}

CARP::~CARP()
{
    // delete allocated space if there is pending packet
    for (auto &pair : _arpQueue) {
        auto & list = pair.second;
        for (auto &item : list) {
            delete item.packet;         // delete [1]
            item.packet = nullptr;
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
    //packet_t copy(*packet);
    //copy.buf = new u_char[packet->size];
    //memmove(copy.buf, packet->buf, packet->size);   // in case overlap, use memmove instead

    std::list<ARPQueueItem> & kList = _arpQueue[key.s_addr];
    ARPQueueItem item;
    item.packet = new packet_t(*packet);            // new [1]
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

    packet_t pkt(SIZE_ETHERNET + cARPHeaderLen);
    pkt.sha     = packet->sha;
    pkt.dha     = packet->dha;

    pkt.reserve(SIZE_ETHERNET);
    pkt.put( cARPHeaderLen );
    memcpy(pkt.data, &arp, cARPHeaderLen);

    //packet_t &pkt = *packet;
    //pkt.arphdr  = arp;
    pkt.ept     = ETH_P_ARP;

    _link->transmit(&pkt);

}

void CARP::cache(const ARPHdr *arphdr)
{
    ARPTableItem item;          
    item.ip     = arphdr->spa;
    memcpy(&item.mac, &arphdr->sha, ETH_ALEN);
    item.ttl    = cARPMaxTTL;

    _arpTable.emplace(item.ip, item);           // cache to arp table

}

void CARP::recvARP(packet_t *packet)
{
    debug("<ARP> received.\n");
    ARPHdr *arphdr = (ARPHdr *)packet->data;

    if (ntohs(arphdr->htype) == ARPHRD_ETHER && ntohs(arphdr->ptype) == ETH_P_IP) {
        u_int16_t oper = ntohs(arphdr->oper);

        struct in_addr spa, tpa;
        spa.s_addr = arphdr->spa;
        tpa.s_addr = arphdr->tpa;
        debug("Sender      IP: %s, MAC: %s\n", inet_ntoa(spa), ether_ntoa((struct ether_addr *)arphdr->sha));
        debug("Destination IP: %s, MAC: %s\n", inet_ntoa(tpa), ether_ntoa((struct ether_addr *)arphdr->tha));

        const Device *dev = _link->getDefaultDevice();
        in_addr_t thisDevAddr = dev->ipAddr.s_addr;

        if (arphdr->tpa != thisDevAddr) {
            debug(DBG_DEFAULT, "ARP not to this device, ignore.");
            return;
        }

        if (oper == ARPOP_REPLY) {
            debug(DBG_DEFAULT, "arp reply.  cache and process.");
            cache(arphdr);

            processPendingDatagrams(arphdr->spa);   // notify for pending ip datagram
        }
        else if(oper == ARPOP_REQUEST)  {
            debug(DBG_DEFAULT, "arp request, cache and reply.");
            cache(arphdr);

            replyARP(arphdr);
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
            debug(DBG_DEFAULT, "<ARP> process pending datagrams for %s...", inet_ntoa(*(struct in_addr*)&addr));
            log("<ARP> process pending datagrams for %s...\n", inet_ntoa(*(struct in_addr*)&addr));
            _link->transmit(item.packet);
            delete item.packet;         // delete [1]
        }

        _arpQueue.erase(it);
    }

}

void CARP::replyARP(const ARPHdr *arphdr)
{
    packet_t packet(ETH_HLEN + cARPHeaderLen); 
    ARPHdr arp; 

    arp = *arphdr;
    arp.oper    = htons(ARPOP_REPLY);

    const Device *dev = _link->getDefaultDevice();
    memcpy(&arp.sha, &dev->hAddr, ETH_ALEN);
    arp.spa     = dev->ipAddr.s_addr;
    memcpy(&arp.tha, &arphdr->sha, ETH_ALEN);
    arp.tpa     = arphdr->spa;

    memcpy(&packet.dha, &arphdr->sha, ETH_ALEN);
    memcpy(&packet.sha, &arp.sha, ETH_ALEN);
    packet.ept  = ETH_P_ARP;

    packet.reserve(ETH_HLEN);
    packet.put(cARPHeaderLen);
    memcpy(packet.data, &arp, cARPHeaderLen);

    struct in_addr tpa {.s_addr = arp.tpa };
    debug(DBG_DEFAULT, "<ARP> reply to %s.", inet_ntoa(tpa));
    log("<ARP> reply to %s.\n", inet_ntoa(tpa));
    _link->transmit(&packet);

}
