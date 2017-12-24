#include "CheckSum.h"

uint16_t cksum(const u_char *const buf, size_t size)
{
    uint32_t sum;
    uint16_t *p = (uint16_t *)buf;

    sum = 0;
    while(size > 1) {
        sum += *p++;
        size -= 2;
    }

    // padding as needed
    if(size == 1) {
        sum += *((u_char *)p);
    }

    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)((~sum) & 0xFFFF);
}
