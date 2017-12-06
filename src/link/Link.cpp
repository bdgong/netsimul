#include "Link.h"
#include "Util.h"
#include <cstring>

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
    ether_header etherhdr;
    memcpy(&etherhdr.ether_shost, &packet->sha, ETH_ALEN);
    memcpy(&etherhdr.ether_dhost, &packet->dha, ETH_ALEN);
    etherhdr.ether_type     = htons(packet->ept); 

    u_int16_t size = 0;
    u_int8_t *buf = nullptr;
    u_int16_t nFrameData = 0;
    u_int8_t *pFrameData = nullptr;
    switch (packet->ept) {
        case ETH_P_ARP:
            nFrameData = cARPHeaderLen;
            pFrameData = (u_int8_t *)&packet->arphdr;
            //size = ETH_HLEN + cARPHeaderLen + ETH_FCS_LEN;
            //if (size < ETH_ZLEN) 
                //size = ETH_ZLEN;
            //buf = new u_int8_t[size]{0};
            //memcpy(buf, &etherhdr, ETH_HLEN);
            //memcpy(buf + ETH_HLEN, &(packet->arphdr), cARPHeaderLen);
            break;
        case ETH_P_IP:
            nFrameData = packet->size;
            pFrameData = packet->buf;
            //size = ETH_HLEN + packet->size + ETH_FCS_LEN;
            //if (size < ETH_ZLEN) 
                //size = ETH_ZLEN;
            //buf = new u_int8_t[size]{0};
            //memcpy(buf, &etherhdr, ETH_HLEN);
            //memcpy(buf + ETH_HLEN, packet->buf, packet->size);
            break;
        default:
            error("Not supported ethernet packet type: %d.\n", packet->ept);
            return ;
    }

    size = ETH_HLEN + nFrameData + ETH_FCS_LEN;
    if (size < ETH_ZLEN) 
        size = ETH_ZLEN;
    buf = new u_int8_t[size]{0};
    memcpy(buf, &etherhdr, ETH_HLEN);
    memcpy(buf + ETH_HLEN, pFrameData, nFrameData);

    _hardware->transmit(buf, size);
    delete[] buf;

}

void CLink::received(const u_char *bytes, size_t size)
{
    //debug("<Link> received:\n");
    packet_t packet;
    packet.rcvbuf   = bytes + ETH_HLEN;
    packet.size     = size - ETH_HLEN;

    struct ether_header *etherhdr = (struct ether_header *)bytes;
    memcpy(&packet.dha, &etherhdr->ether_dhost, ETH_ALEN);
    memcpy(&packet.sha, &etherhdr->ether_shost, ETH_ALEN);
    packet.ept  = ntohs(etherhdr->ether_type);

    debug("Network Layer Protocol: %s (%04X)\n",
            tok2str(ethertype_values, "Unknown", packet.ept), packet.ept);
    debug("Destination MAC: %s\n", ether_ntoa(&packet.dha));
    debug("Sender      MAC: %s\n", ether_ntoa(&packet.sha));

    switch (packet.ept) {
        case ETH_P_ARP:
            _neigh->received(&packet);
            break;
        case ETH_P_IP:
            debug("not handled\n");
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
    _neigh->init();
    _isInited   = true;
    debug("Link inited.\n");

}
