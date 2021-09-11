#include "packethead.h"
#include <stdio.h>
#pragma once

typedef struct packet_headers
{
    const eth_hdr *eth;
    const arp_hdr *arph;
    const ip4_hdr *ip4h;
    const ip6_hdr *ip6h;
    const tcp_hdr *tcph;
    const udp_hdr *udph;
    const icmp_hdr *icmph;
} header_s;

typedef struct rule
{
    char *ipver;
    char *ptc;
    char *srcip;
    char *srcport;
    char *dstip;
    char *dstport;
    bit8_t ignore;
} rule;

typedef struct counts
{
    long long int arp;
    long long int tcp;
    long long int udp;
    long long int icmp;
    long long int ipv4;
    long long int ipv6;
} count_s;

char *strmac(const bit8_t[ETH_ADDR_LEN]);
char *strip4(const bit8_t[IP4_ADDR_LEN]);
char *strip6(const bit16_t[IP6_ADDR_LEN]);
bit32_t e_ntohl(bit32_t);
bit16_t e_ntohs(bit16_t);