#include "Neighbor.h"

#include "Util.h"

void CNeighbor::init()
{
    if (_isInited)
        return;

    _link       = CLink::instance();
    _link->init();

    _arp        = CARP::instance();
    _arp->init();

    _isInited   = true;
    debug("Neighbor initied.\n");
}

void CNeighbor::send(packet_t *packet)
{
    _arp->sendDatagram(packet);
}

void CNeighbor::received(packet_t *packet)
{
    _arp->recvARP(packet);

}
