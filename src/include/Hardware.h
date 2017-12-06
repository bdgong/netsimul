#pragma once
//#ifndef HARDWARE_H_
//#define HARDWARE_H_

#include "Device.h"
#include "packet.h"
#include "Link.h"

#include <pcap/pcap.h>

#include <list>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
#define PKT_BUFF_TIME 2000

class CLink;

class CHardware
{
public:
    // 
    static CHardware * instance()
    {
        static CHardware hardware;
        return &hardware;
    }

    ~CHardware() 
    {
        if (_defaultDev != nullptr && _defaultDev->handler != nullptr) {
            pcap_close(_defaultDev->handler);
        }
        pcap_freealldevs(_foundDevs); 
    }

    void init();
    void up();
    void down();
    void transmit(const u_char*, size_t size);
    void received();

    const Device * getDefaultDevice() const 
    {
        return _defaultDev;
    }

private:
    bool _isInited;

    pcap_if_t *_foundDevs;          // found pcap devices

    std::list<Device> _devs;        // avaliable device list
    Device *_defaultDev;            // default device

    CLink *_link;

    void detectDevices(char *errbuf);

    static void getPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

    CHardware() : _isInited(false), _defaultDev(nullptr), _link(nullptr)
    {
    }

    CHardware(const CHardware&);
    CHardware& operator= (const CHardware&);
};

//#endif // HARDWARE_H_
