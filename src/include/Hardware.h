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
        pcap_freealldevs(_foundDevs); 
    }

    void init();
    void up(Device *);
    void down(Device *);
    void transmit(packet_t *);
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

    CHardware() : _isInited(false), _defaultDev(nullptr), _link(nullptr)
    {
    }

    CHardware(const CHardware&);
    CHardware& operator= (const CHardware&);
};

//#endif // HARDWARE_H_
