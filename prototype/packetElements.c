#include "packetElements.h"

char *strmac(const bit8_t addr[ETH_ADDR_LEN])
{
    static char saddr[18];
    sprintf(saddr, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return saddr;
}

char *strip4(const bit8_t addr[IP4_ADDR_LEN])
{
    static char saddr[16];
    sprintf(saddr, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    return saddr;
}

char *strip6(const bit16_t addr[IP6_ADDR_LEN])
{
    static char saddr[40];
    sprintf(saddr, "%x:%x:%x:%x:%x:%x:%x:%x", e_ntohs(addr[0]), e_ntohs(addr[1]), e_ntohs(addr[2]), e_ntohs(addr[3]), e_ntohs(addr[4]), e_ntohs(addr[5]), e_ntohs(addr[6]), e_ntohs(addr[7]));
    return saddr;
}

bit16_t e_ntohs(bit16_t hex)
{
    return (hex & 0x00ff) << 8 | (hex & 0xff00) >> 8;
}

bit32_t e_ntohl(bit32_t hex)
{
    return (hex & 0xff000000) >> 24 | (hex & 0x00ff0000) >> 8 | (hex & 0x0000ff00) << 8 | (hex & 0x000000ff) << 24;
}