#include "TCP.h"
#include "Network.h"
#include "Util.h"

#define TAG "<CTCP> "

void CTCP::init()
{
    if (_isInited)
        return;

    CNetwork::instance()->init();
    _isInited = true;
    debug(DBG_DEFAULT, " inited.");
}

CTCP::~CTCP()
{
    log(TAG "desconstructed.\n");
}

