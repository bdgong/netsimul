#include "UDP.h"

#include "Util.h"
#include <string>

const unsigned int cMaxBufferSize = 4096;

void CUDP::init()
{
    if (_isInited)
        return ;

    _isInited = true;
    debug(DBG_DEFAULT, "<UDP> inited.");
}

void CUDP::send(packet_t *pkt)
{
}

void CUDP::received(packet_t *pkt)
{
    debug(DBG_DEFAULT, "<UDP> received.");
    udphdr_t *udphdr = (udphdr_t *)pkt->data;
    uint16_t dataLen = ntohs( udphdr->uh_len ) - SIZE_UDP;

    pkt->pull(SIZE_UDP);
    std::string msg((const char*)pkt->data, dataLen);

    debug(DBG_DEFAULT, "Received data length=%d : \n%s", dataLen, msg.c_str());

}

