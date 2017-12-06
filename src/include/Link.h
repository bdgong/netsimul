#pragma once
//#ifndef LINK_H_
//#define LINK_H_

#include "Hardware.h"
#include "Neighbor.h"
#include "packet.h"

#include <memory>

class CNeighbor;
class CHardware;

/*
 * CLink - link layer interface 
 *
 * Call neighbor subsystem when send a network datagram.
 * Call hardware when transmit a packet.
 * */
class CLink
{
public:
    static CLink * instance()
    {
        static CLink inst;
        return &inst;
    }

    ~CLink() 
    {
    }

    void init();
    /*
     * transmit a packet
     * */
    void transmit(packet_t *);

    /*
     * send a network datagram
     * */
    void send(packet_t *packet);

    /*
     * Receive packet from device
     * */
    void received(const u_char *, size_t);

    /*
     * The default device used to send and receive packet
     * */
    const Device * getDefaultDevice() const;

private:
    bool _isInited;
    CNeighbor *_neigh;
    CHardware *_hardware;

    CLink() : _isInited(false), _hardware(nullptr), _neigh(nullptr)
    {
        // do not call init() here, will cause '__gnu_cxx::recursive_init_error'
    }

    CLink(const CLink&);
    CLink & operator= (const CLink&);
};

//#endif  // LINK_H_
