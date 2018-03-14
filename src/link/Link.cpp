#include "Link.h"
#include "Util.h"
#include <cstring>
#include <netinet/ether.h>

#define TAG "<Link> "

const tok_t ethertype_values[] = {
    {ETH_P_IP,          "IPv4"},
    {ETH_P_ARP,         "ARP"},
    {ETH_P_IPV6,        "IPv6"},
    {ETH_P_LOOPBACK,    "Loopback"},
    {0, NULL}
};

void CLink::send(packet_t *packet)
{
    _neigh->send(packet);
}

void CLink::transmit(packet_t *packet)
{
    log(TAG "%s.\n", __func__);
    if ( !(packet->ept == ETH_P_ARP || packet->ept == ETH_P_IP) ) {
        error("Unsupported ethernet packet.\n");
        return ;
    }

    ether_header etherhdr;
    memcpy(&etherhdr.ether_shost, &packet->sha, ETH_ALEN);
    memcpy(&etherhdr.ether_dhost, &packet->dha, ETH_ALEN);
    etherhdr.ether_type     = htons(packet->ept); 

    log (TAG "%s(): From %s.\n", __func__, ether_ntoa((ether_addr*)&etherhdr.ether_shost));
    log (TAG "%s(): To   %s.\n", __func__, ether_ntoa((ether_addr*)&etherhdr.ether_dhost));

    packet->push(ETH_HLEN);
    memcpy(packet->data, &etherhdr, ETH_HLEN);
    _hardware->transmit(packet->data, packet->len);

}

void CLink::received(const u_char *bytes, size_t size)
{
    //debug("<Link> received:\n");
    packet_t packet(size);
    packet.put(size);
    memcpy(packet.data, bytes, size);

    struct ether_header *etherhdr = (struct ether_header *)packet.data;
    memcpy(&packet.dha, &etherhdr->ether_dhost, ETH_ALEN);
    memcpy(&packet.sha, &etherhdr->ether_shost, ETH_ALEN);
    packet.ept  = ntohs(etherhdr->ether_type);

    debug("Network Layer Protocol: %s (%04X)\n",
            tok2str(ethertype_values, "Unknown", packet.ept), packet.ept);
    debug("Destination MAC: %s\n", ether_ntoa(&packet.dha));
    debug("Sender      MAC: %s\n", ether_ntoa(&packet.sha));

    packet.pull(ETH_HLEN);
    switch (packet.ept) {
        case ETH_P_ARP:
            _neigh->received(&packet);
            break;
        case ETH_P_IP:
            _network->received(&packet);
            break;
        default:
            return ;
    }

}

const Device * CLink::getDefaultDevice() const 
{
    return _hardware->getDefaultDevice();
}

void CLink::init()
{
    if (_isInited)
        return;

    _hardware   = CHardware::instance();
    _hardware->init();
    _neigh      = CNeighbor::instance();
    // Since this init() is called by CNeighbor's init(), it must be initialized
    //   there is no need to call
    //_neigh->init();
    _network = CNetwork::instance();

    _isInited   = true;
    debug(DBG_DEFAULT, TAG "initied.");

}
