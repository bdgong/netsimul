#pragma once
//#ifndef NEIGHBOR_H_
//#define NEIGHBOR_H_

#include "arp.h"
#include "packet.h"

class CARP;

/*
 * CNeighbor - neighbor subsystem 
 * */
class CNeighbor
{
public:
    // 
    static CNeighbor * instance()
    {
        static CNeighbor inst;
        return &inst;
    }

    void init();

    void send(packet_t *packet);

    void received();
private:
    bool _isInited;
    CARP *_arp;

    CNeighbor() : _isInited(false), _arp(nullptr)
    {
    }

    CNeighbor(const CNeighbor &);
    CNeighbor & operator= (const CNeighbor &);

};

//#endif // NEIGHBOR_H_
