#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "packethead.h"

#define MAX_PACKET_SIZE 8192

char* strmac(const bit8_t[ETH_ADDR_LEN]);
char* strip4(const bit8_t[IP4_ADDR_LEN]);
char* strip6(const bit16_t[IP6_ADDR_LEN]);
bit16_t ntohs(bit16_t);
void pcapfatal(const char *, const char *);
void callback_packet(bit8_t*, const struct pcap_pkthdr*, const bit8_t*);

const eth_hdr* eth;
const arp_hdr* arph;
const ip4_hdr* ip4h;
const ip6_hdr* ip6h;
const tcp_hdr* tcph;
const udp_hdr* udph;

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <Interface>", argv[0]);
        exit(-1);
    }
    int i;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 0, 0, errbuf);

    if (handle == NULL)
    {
        pcapfatal("pcap_open_live", errbuf);
        exit(-1);
    }

    fprintf(stdout, "[Debug Mode]\n");

    pcap_loop(handle, -1, callback_packet, errbuf);
    
    pcap_close(handle);
    return 0;
}

char* strmac(const bit8_t addr[ETH_ADDR_LEN]) {
    static char saddr[18];
    sprintf(saddr, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return saddr;
}

char* strip4(const bit8_t addr[IP4_ADDR_LEN]) {
    static char saddr[16];
    sprintf(saddr, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    return saddr;
}

char* strip6(const bit16_t addr[IP6_ADDR_LEN]) {
    static char saddr[40];
    sprintf(saddr, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
    return saddr;
}

bit16_t ntohs(bit16_t hex)
{
    return (hex & 0x00ff) << 8 | (hex & 0xff00) >> 8;
}

void pcapfatal(const char *inerr, const char *errbuf)
{
    fprintf(stderr, "Fatal error in %s : %s\n", inerr, errbuf);
    exit(-1);
}

void callback_packet(bit8_t* args, const struct pcap_pkthdr* header, const bit8_t* packet) {
    fprintf(stdout, "------------------------------\n");

    eth = (const eth_hdr*)packet;
    fprintf(stdout, "[ETH]\n");
    fprintf(stdout, "eth_src_mac: %s\n", strmac(eth->eth_src_mac));
    fprintf(stdout, "eth_dst_mac: %s\n", strmac(eth->eth_dst_mac));
    fprintf(stdout, "eth_type: 0x%04x\n", ntohs(eth->eth_type));

    if(ntohs(eth->eth_type) == 0x0806) { //arp
        arph = (const arp_hdr*)(sizeof(eth_hdr) + packet);

        fprintf(stdout, "[ARP]\n");
        fprintf(stdout, "Hardware type: %d\n", ntohs(arph->arp_hard_type));
        fprintf(stdout, "Protocol type: 0x%04x\n", ntohs(arph->arp_protocol));
        fprintf(stdout, "Hardware size: %d\n", arph->arp_addr_len);
        fprintf(stdout, "Protocol size: %d\n", arph->arp_protocol_len);
        fprintf(stdout, "Opcode: %d\n", ntohs(arph->arp_opcode));
        fprintf(stdout, "src mac addr: %s\n", strmac(arph->arp_src_mac));
        fprintf(stdout, "src ip addr: %s\n", strip4(arph->arp_src_ip));
        fprintf(stdout, "dst mac addr: %s\n", strmac(arph->arp_dst_mac));
        fprintf(stdout, "dst ip addr: %s\n", strip4(arph->arp_dst_ip));

    }else if(ntohs(eth->eth_type) == 0x0800) { // ipv4
        ip4h = (const ip4_hdr*)(sizeof(eth_hdr) + packet);
       
        fprintf(stdout, "[IPv4]\n");
        fprintf(stdout, "Version: %d\n", ip4h->ip4_ver);
        fprintf(stdout, "Header length: %d\n", ip4h->ip4_hdrlen*4);
        fprintf(stdout, "Type of Service: 0x%02x\n", ip4h->ip4_tos);
        fprintf(stdout, "Total Length: %d\n", ntohs(ip4h->ip4_tot_len));
        fprintf(stdout, "Identification: 0x%04x\n", ntohs(ip4h->ip4_id));
        fprintf(stdout, "Flags: 0x%04x\n", ntohs(ip4h->ip4_frag_off) & 0xe000);
        fprintf(stdout, "Fragment offset: %d\n", ntohs(ip4h->ip4_frag_off) & 0x1fff);
        fprintf(stdout, "Time to Live: %d\n", ip4h->ip4_ttl);
        fprintf(stdout, "Protocol: %d\n", ip4h->ip4_protocol);
        fprintf(stdout, "Header checksum: 0x%04x\n", ntohs(ip4h->ip4_checksum));
        fprintf(stdout, "src: %s\n", strip4(ip4h->ip4_src_ip));
        fprintf(stdout, "dst: %s\n", strip4(ip4h->ip4_dst_ip));

        if(ip4h->ip4_protocol == 6) { // tcp
            tcph = (const tcp_hdr*)(sizeof(eth_hdr) + sizeof(ip4_hdr) + packet);
            
            fprintf(stdout, "[TCP]\n");
            fprintf(stdout, "Source Port: %d\n", ntohs(tcph->tcp_src_port));
            fprintf(stdout, "Destination Port: %d\n", ntohs(tcph->tcp_dst_port));
            fprintf(stdout, "Sequnce number: %d\n", ntohl(tcph->tcp_seq));
            fprintf(stdout, "Acknowledgment number: %d\n", ntohl(tcph->tcp_ack));
            fprintf(stdout, "Header Length: %d\n", tcph->tcp_hlen*4);
            fprintf(stdout, "Flags: 0x%03x", tcph->tcp_flags);
            fprintf(stdout, "Window size value: %d\n", ntohs(tcph->tcp_window));
            fprintf(stdout, "Checksum: 0x%04x\n", ntohs(tcph->tcp_checksum));
            fprintf(stdout, "Urgent pointer: %d\n", ntohs(tcph->tcp_urgent));

        } else if(ip4h->ip4_protocol == 17) { // udp
            udph = (const udp_hdr*)(sizeof(eth_hdr) + sizeof(ip4_hdr) + packet);

        }
    }else if(ntohs(eth->eth_type) == 0x08dd) { // ipv6
        ip6h = (const ip6_hdr*)(sizeof(eth_hdr) + packet);
       
        if(ip6h->ip6_next == 6) { // tcp
            tcph = (const tcp_hdr*)(sizeof(eth_hdr) + sizeof(ip6_hdr) + packet);

        }else if(ip6h->ip6_next == 17) { // udp
            udph = (const udp_hdr*)(sizeof(eth_hdr) + sizeof(ip6_hdr) + packet);

        }
    }

    fprintf(stdout, "------------------------------\n\n");
}