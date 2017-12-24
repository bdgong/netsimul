#include "Network.h"

#include "Util.h"

void CNetwork::send(packet_t *pkt)
{
    // assume no fragment needed
    _neigh->send(pkt);
}

void CNetwork::forward(packet_t *pkt)
{
}

void CNetwork::deliver(packet_t *pkt)
{
}

void CNetwork::init()
{
    if (_isInited)
        return;

    _neigh = CNeighbor::instance();
    _neigh->init();

    _isInited = true;
    debug(DBG_DEFAULT, "<Network> inited");

}

