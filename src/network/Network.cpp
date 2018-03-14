#include "Network.h"

#include "ip.h"
#include "CheckSum.h"
#include "Util.h"

#include <cstring>
#include <algorithm>

#define TAG "<Network> "

const tok_t ipproto_values[] = {
    {IPPROTO_TCP, "TCP"},
    {IPPROTO_UDP, "UDP"},
    {IPPROTO_ICMP, "ICMP"},
    {IPPROTO_IP, "IP"},
    {0, NULL}
};

/*
 * A simple implementation of `ip_select_fb_ident()`
 * */
uint16_t CNetwork::getAndIncID(packet_t *pkt)
{
    in_addr_t daddr = pkt->daddr.s_addr;

    uint16_t id;
    if (_idMap.count(daddr) == 1) {
        // find it
        id = _idMap.at(daddr) + 1;
    }
    else {
        // not found, create one
        srand((unsigned int)time(NULL));
        id = rand() % 0xFFFF;
    }
    _idMap[daddr] = id;         // update cache
    return id;

}

void CNetwork::send(packet_t *pkt)
{
    log (TAG "%s.\n", __func__);
    if (pkt->len > 0xFFFF) {
        debug(DBG_DEFAULT, "Too big packet to send.");
        return ;
    }

    pkt->ept     = ETH_P_IP;

    const Device *dev = CLink::instance()->getDefaultDevice();
    uint16_t mtu = dev->mtu;

    if (SIZE_IP + pkt->len > mtu) {
        fragment(pkt, mtu);
    }
    else {
        // prepare IP header
        iphdr_t ip;
        size_t size_new = SIZE_IP + pkt->len; 

        ip.ip_vhl   = 0x45;
        ip.ip_tos   = 0;
        ip.ip_len   = htons(size_new);
        ip.ip_id    = htons(getAndIncID(pkt));
        ip.ip_off   = htons(IP_DF);     // don't fragment
        ip.ip_ttl   = IPDEFTTL;         // default TTL
        ip.ip_p     = pkt->proto;
        ip.ip_sum   = 0;
        ip.ip_src   = pkt->saddr;
        ip.ip_dst   = pkt->daddr;

        ip.ip_sum   = cksum((u_char *)&ip, SIZE_IP);

        // push IP header space
        pkt->push(SIZE_IP);
        // copy IP header
        memcpy(pkt->data, &ip, SIZE_IP);

        char *srcIP = inet_ntoa(ip.ip_src);
        char *dstIP = inet_ntoa(ip.ip_dst);
        log (TAG "%s() : from source    %s\n", __func__, inet_ntoa(ip.ip_src));
        log (TAG "%s() : to destination %s\n", __func__, inet_ntoa(ip.ip_dst));
        _neigh->send(pkt);
    }

}

void CNetwork::fragment(packet_t *pkt, uint16_t mtu)
{
    debug(DBG_DEFAULT, TAG "Do fragment.");
    iphdr_t ip;

    ip.ip_vhl   = 0x45;
    ip.ip_tos   = 0;
    //ip.ip_len   = htons(size_new);
    ip.ip_id    = htons(getAndIncID(pkt));
    //ip.ip_off   = htons(IP_DF);    // don't fragment
    ip.ip_ttl   = IPDEFTTL;         // default TTL
    ip.ip_p     = pkt->proto;
    ip.ip_sum   = 0;
    ip.ip_src   = pkt->saddr;
    ip.ip_dst   = pkt->daddr;

    unsigned int left   = pkt->len; // total length
    unsigned int len    = 0;        // current fragment length
    unsigned char *ptr  = pkt->data;// fragment start position
    uint16_t offset     = 0;


    while (left > 0) {
        len = left;

        if (len + SIZE_IP > mtu) {
            len = mtu - SIZE_IP;
        }

        if (len < left) {
            len &= ~7;          // align eight byte 
        }

        debug(DBG_DEFAULT, TAG "data left length=%d, now length=%d.", left, len);

        left -= len;

        // allocate fragment packet 
        packet_t pkt2(ETH_HLEN + SIZE_IP + len); 
        pkt2.copyMetadata(*pkt);
        pkt2.reserve(ETH_HLEN + SIZE_IP);
        pkt2.put(len);
        memcpy(pkt2.data, ptr, len);

        // set ip header
        iphdr_t iphdr = ip;

        iphdr.ip_len    = htons(SIZE_IP + len);
        iphdr.ip_off    = htons(offset >> 3);

        if (left > 0) {
            iphdr.ip_off |= htons(IP_MF);
        }

        iphdr.ip_sum    = cksum((u_char *)&iphdr, SIZE_IP);

        pkt2.push(SIZE_IP);
        memcpy(pkt2.data, &iphdr, SIZE_IP);

        offset += len;
        ptr += len;

        debug(DBG_DEFAULT, "<Network> send out fragment: %d bytes.", len);
        _neigh->send(&pkt2);

    } // while

}

void CNetwork::forward(packet_t *pkt)
{
    debug(DBG_DEFAULT, TAG "forward to be implemented.");
}

void CNetwork::deliver(packet_t *pkt)
{
    //pkt->pull(SIZE_IP);

    switch (pkt->proto) {
        case IPPROTO_TCP:
            {
                CTCP::instance()->received(pkt);
                break;
            }
        case IPPROTO_UDP:
            {
                CUDP::instance()->received(pkt);
                break;
            }
        case IPPROTO_ICMP:
            {
                break;
            }
        case IPPROTO_IP:
            {
                break;
            }
        default:
            break;
    }

}

uint32_t CNetwork::fragmentHashCode(iphdr_t *iphdr)
{
    uint32_t sAddrVal   = iphdr->ip_src.s_addr;
    uint32_t dAddrVal   = iphdr->ip_dst.s_addr;
    uint32_t protocol   = iphdr->ip_p;
    uint32_t id         = iphdr->ip_id;

    //return sAddrVal * 3 + dAddrVal * 5 + protocol * 17 + id * 31;
    return ((sAddrVal << 1) + sAddrVal)
        + ((dAddrVal << 2) + dAddrVal)
        + ((protocol << 4) + protocol)
        + ((id << 5) - id);

}

void CNetwork::defragment(iphdr_t *iphdr, packet_t *pkt)
{
    // assume no overlap 
    debug(DBG_DEFAULT,  "defragment.");

    // find fragment list it belongs to in fragment map
    uint32_t keyFrag = fragmentHashCode(iphdr);

    IPFragList *pThisFrags = nullptr;
    if (_fragsMap.count(keyFrag) == 1) {
        pThisFrags = &_fragsMap.at(keyFrag);    // found and return the address
    }
    else {
        pThisFrags = &_fragsMap[keyFrag];       // not found, create one and return the address

        pThisFrags->saddr   = iphdr->ip_src;
        pThisFrags->daddr   = iphdr->ip_dst;
        pThisFrags->proto   = iphdr->ip_p;
        pThisFrags->id      = iphdr->ip_id;
        pThisFrags->len     = 0;
        pThisFrags->meat    = 0;
    }

    // calculate offset 
    uint16_t offset = ntohs(iphdr->ip_off);
    uint16_t flags = offset & ~IP_OFFMASK;
    offset &= IP_OFFMASK;
    offset <<= 3;

    uint16_t end = offset + pkt->len - SIZE_IP;

    if (offset == 0) {
        // first fragment
    }

    if ((flags & IP_MF) == 0) {
        // last fragment
        pThisFrags->len = end;
    }

    // copy and insert this fragment to framgent list
    pkt->pull(SIZE_IP);

    packet_t *pkt2 = new packet_t(*pkt);
    pkt2->copyMetadata(*pkt);
    pkt2->getPacketCB()->offset = offset;

    std::list<packet_t *> &frags = pThisFrags->fragments;
    const auto it = std::find_if(frags.cbegin(), frags.cend(), [=](const packet_t *pkt) {
                return pkt->getPacketCB()->offset >= offset;
            });
    frags.insert(it, pkt2);

    debug(DBG_DEFAULT, TAG "fragment length=%d.", pkt2->len);
    pThisFrags->meat += pkt2->len;
    if (pThisFrags->meat == pThisFrags->len) {
        // completed, do reassemble work
        reasm(pThisFrags);

        // clear cache
        clear(pThisFrags);
        // remove item from map
        _fragsMap.erase(keyFrag);
    }
    
}

void CNetwork::reasm(IPFragList *pFrags)
{
    debug(DBG_DEFAULT, TAG "reassemble fragments of datagram id=%d.", pFrags->id);
    packet_t pkt(pFrags->len);
    pkt.saddr = pFrags->saddr;
    pkt.daddr = pFrags->daddr;
    pkt.proto = pFrags->proto;
    
    std::list<packet_t *> &frags = pFrags->fragments;
    for (packet_t *fragment : frags) {
        pkt.put(fragment->len);

        memcpy(pkt.data, fragment->data, fragment->len);

        pkt.pull(fragment->len);
    }

    pkt.resetData();
    deliver(&pkt);
}

void CNetwork::clear(IPFragList *pFrags)
{
    debug(DBG_DEFAULT, TAG "clear fragments of datagram id=%d.", pFrags->id);
    std::list<packet_t *> &frags = pFrags->fragments;
    auto it = frags.begin();
    while ( it != frags.end() ) {
        packet_t *pkt = *it;
        delete pkt;
        it = frags.erase(it);
    }

}

void CNetwork::received(packet_t *pkt)
{
    debug(DBG_DEFAULT, "<Network> received.");
    iphdr_t *iphdr = (iphdr_t *)pkt->data;

    if (IP_HL(iphdr)*4 < 20) {
        error("Invalid ip header.\n");
        return ;
    }

    pkt->saddr = iphdr->ip_src;
    pkt->daddr = iphdr->ip_dst;
    pkt->proto = iphdr->ip_p;

    /* print source and destination IP addresses */
    debug("       From: %s\n", inet_ntoa(pkt->saddr));
    debug("         To: %s\n", inet_ntoa(pkt->daddr));
    debug("   Protocol: %s (%03d)\n",
            tok2str(ipproto_values, "Unknown", pkt->proto), pkt->proto);

    // check for local deliver or forward by compare destination address
    const Device *dev = CLink::instance()->getDefaultDevice();
    if (dev->ipAddr.s_addr != pkt->daddr.s_addr ) {
        forward(pkt);
    }
    else {
        if (iphdr->isFragment()) {
            defragment(iphdr, pkt);
        }
        else {
            pkt->pull(SIZE_IP);
            deliver(pkt);
        }
    }
    
}

CNetwork::~CNetwork() 
{
    // delete still hold cache if needed
    for (auto pair : _fragsMap) {
        IPFragList *pFrags = &pair.second;

        clear(pFrags);
    }
    _fragsMap.clear();

}

void CNetwork::init()
{
    if (_isInited)
        return;

    _neigh = CNeighbor::instance();
    _neigh->init();

    _isInited = true;
    debug(DBG_DEFAULT, "<Network> inited.");

}

