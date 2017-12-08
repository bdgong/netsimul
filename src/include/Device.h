#ifndef DEVICE_H_
#define DEVICE_H_

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <pcap/pcap.h>

#include <iostream>
#include <sstream>

typedef struct device {
    u_int16_t           id;
    u_int16_t           type;
    char                *name;
    struct in_addr      ipAddr;     // ip
    struct ether_addr   hAddr;      // mac

    pcap_t              *handler;   // pcap packet handler

    device ()
    {
        id = type = 0;
        name = nullptr;
        handler = nullptr;
    }

    void show() const
    {
        std::cout << toString() << std::endl;
    }

    std::string toString() const
    {
        std::ostringstream oss;
        oss << "Device ["
            << "id=" << id
            << ", type=" << type
            << ", name=" << name
            << ", ip=" << inet_ntoa(ipAddr)
            << ", mac=" << ether_ntoa(&hAddr)
            << "]";
        return oss.str();
    }

} Device; 

#endif  // DEVICE_H_
