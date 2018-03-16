#include "Neighbor.h"

#include "Util.h"

#define TAG "<Neighbor> "

void CNeighbor::init()
{
    if (_isInited)
        return;

    _arp        = CARP::instance();
    _arp->init();

    _link       = CLink::instance();
    _link->init();

    _isInited   = true;
    debug(DBG_DEFAULT, TAG "initied.");
}

void CNeighbor::send(packet_t *packet)
{
    _arp->sendDatagram(packet);
}

void CNeighbor::received(packet_t *packet)
{
    _arp->recvARP(packet);

}
