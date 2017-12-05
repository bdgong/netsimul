#include "Link.h"
#include "Util.h"
#include <cstring>

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

    u_int8_t *buf = nullptr;
    u_int16_t size = 0;
    switch (packet->ept) {
        case ETH_P_ARP:
            size = ETH_HLEN + cARPHeaderLen + ETH_FCS_LEN;
            if (size < ETH_ZLEN) 
                size = ETH_ZLEN;
            buf = new u_int8_t[size]{0};
            memcpy(buf, &etherhdr, ETH_HLEN);
            memcpy(buf + ETH_HLEN, &(packet->arphdr), cARPHeaderLen);
            break;
        case ETH_P_IP:
            break;
        default:
            error("Not supported ethernet packet type: %d.\n", packet->ept);
            return ;
    }

    if(buf != nullptr) {
        packet_t pkt    = *packet; 
        pkt.size        = size;
        pkt.buf         = buf;

        _hardware->transmit(&pkt);

        delete[] buf;
        //pkt.buf = buf = nullptr;
    }

}

const Device * CLink::getDefaultDevice() const 
{
    return _hardware->getDefaultDevice();
}
