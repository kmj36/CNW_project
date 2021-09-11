#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <arpa/inet.h>
#include "packethead.h"
#include "packetElements.h"

#define MAX_PACKET_SIZE 8192

void checkrule(bit8_t);
void pcapfatal(const char *, const char *);
void callback_packet(bit8_t *, const struct pcap_pkthdr *, const bit8_t *);
void printmatchresult(void);
void freerules();
void printmotd(const char *);
bit8_t analyze(const bit8_t *);
count_s *initcount_m(void);
rule **readinirule_m(int fd);

void print_eth(void);
void print_arp(void);
void print_icmp(void);
void print_ipv4(void);
void print_ipv6(void);
void print_tcp(void);
void print_udp(void);

static header_s *pheaders = NULL;
static rule **readrules = NULL;
static count_s *packetcount = NULL;
static count_s *rulecount = NULL;
static pcap_t *handle = NULL;
static int count = 0;

void sig_handler(int signum)
{
    pcap_close(handle);
    handle = NULL;

    free(pheaders);
    pheaders = NULL;

    freerules();
    readrules = NULL;

    printmatchresult();

    free(packetcount);
    packetcount = NULL;

    free(rulecount);
    rulecount = NULL;

    fprintf(stdout, "CNW_IDS exiting\n");
    exit(0);
}

void main(int argc, char *argv[])
{
    int fd, i;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct sigaction act;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: sudo %s <Interface>", argv[0]);
        exit(-1);
    }
    if ((fd = open("./rule.ini", O_RDONLY)) == -1)
    {
        fprintf(stderr, "The rules file \"rule.ini\" does not exist.");
        exit(-1);
    }

    handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 0, 0, errbuf);
    packetcount = initcount_m();
    rulecount = initcount_m();
    readrules = readinirule_m(fd);
    pheaders = malloc(sizeof(header_s));

    if (handle == NULL)
    {
        pcapfatal("pcap_open_live", errbuf);
        exit(-1);
    }

    act.sa_handler = sig_handler;
    sigfillset(&(act.sa_mask));
    sigaction(SIGINT, &act, NULL);

    printmotd(argv[1]);

    pcap_loop(handle, -1, callback_packet, errbuf);
}

void pcapfatal(const char *inerr, const char *errbuf)
{
    fprintf(stderr, "Fatal error in %s : %s\n", inerr, errbuf);
    exit(-1);
}

count_s *initcount_m()
{
    count_s *temp = malloc(sizeof(count_s));
    temp->icmp = temp->ipv4 = temp->ipv6 = temp->tcp = temp->udp = 0;
    return temp;
}

rule **readinirule_m(int fd) // 버그 없음
{
    rule **result;
    int rulesize = lseek(fd, 0, SEEK_END);
    char *rulestr = malloc(sizeof(char) * rulesize), *temp;

    lseek(fd, 0, SEEK_SET);
    read(fd, rulestr, rulesize);

    temp = strtok(rulestr, " >\n");

    if (strcmp(temp, "---") == 0)
    {
        fprintf(stderr, "Fatal error in strtok() : No rules\n");
        exit(-1);
    }
    else
        result = malloc(sizeof(rule *));

    while (1)
    {
        result[count] = malloc(sizeof(rule));
        result[count]->ignore = 0;

        result[count]->ipver = malloc(strlen(temp)); // ip 버전
        strcpy(result[count]->ipver, temp);

        if (strcmp(result[count]->ipver, "any") == 0)
            result[count]->ignore |= 1;

        temp = strtok(NULL, " >\n");

        result[count]->ptc = malloc(strlen(temp)); // 프로토콜
        strcpy(result[count]->ptc, temp);

        if (strcmp(result[count]->ptc, "any") == 0)
            result[count]->ignore |= 2;

        temp = strtok(NULL, " >\n");

        result[count]->srcip = malloc(strlen(temp)); // 출발지 ip
        strcpy(result[count]->srcip, temp);

        if (strcmp(result[count]->srcip, "0.0.0.0") == 0 || strcmp(result[count]->srcip, "::") == 0)
            result[count]->ignore |= 4;

        temp = strtok(NULL, " >\n");

        result[count]->srcport = malloc(strlen(temp)); // 출발지 포트
        strcpy(result[count]->srcport, temp);

        if (strcmp(result[count]->srcport, "0") == 0)
            result[count]->ignore |= 8;

        temp = strtok(NULL, " >\n");

        result[count]->dstip = malloc(strlen(temp)); // 도착지 ip
        strcpy(result[count]->dstip, temp);

        if (strcmp(result[count]->dstip, "0.0.0.0") == 0 || strcmp(result[count]->dstip, "::") == 0)
            result[count]->ignore |= 16;

        temp = strtok(NULL, " >\n");

        result[count]->dstport = malloc(strlen(temp)); // 도착지 포트
        strcpy(result[count]->dstport, temp);

        if (strcmp(result[count]->dstport, "0") == 0)
            result[count]->ignore |= 32;

        temp = strtok(NULL, " >\n");

        if (strcmp(temp, "---") == 0 || temp == NULL)
            break;
        else
        {
            count++;
            result = realloc(result, sizeof(rule *) * (count + 1));
        }
    }

    count++;
    free(rulestr);
    rulestr = NULL;

    close(fd);
    return result;
}

void callback_packet(bit8_t *args, const struct pcap_pkthdr *header, const bit8_t *packet)
{
    bit16_t flags = analyze(packet);
    checkrule(flags);
}

bit8_t analyze(const bit8_t *packet)
{
    bit8_t flags = 0;
    pheaders->eth = (const eth_hdr *)packet;
    if (e_ntohs(pheaders->eth->eth_type) == 0x0806)
    {
        pheaders->arph = (const arp_hdr *)(sizeof(eth_hdr) + packet);
        flags |= 1;
        packetcount->arp++;
    }
    else if (e_ntohs(pheaders->eth->eth_type) == 0x0800)
    {
        pheaders->ip4h = (const ip4_hdr *)(sizeof(eth_hdr) + packet);
        packetcount->ipv4++;
        if (pheaders->ip4h->ip4_protocol == 1)
        {
            pheaders->icmph = (const icmp_hdr *)(sizeof(eth_hdr) + (pheaders->ip4h->ip4_hdrlen * 4) + packet);
            flags |= 2;
            packetcount->icmp++;
        }
        else if (pheaders->ip4h->ip4_protocol == 6)
        {
            pheaders->tcph = (const tcp_hdr *)(sizeof(eth_hdr) + (pheaders->ip4h->ip4_hdrlen * 4) + packet);
            flags |= 4;
            packetcount->tcp++;
        }
        else if (pheaders->ip4h->ip4_protocol == 17)
        {
            pheaders->udph = (const udp_hdr *)(sizeof(eth_hdr) + (pheaders->ip4h->ip4_hdrlen * 4) + packet);
            flags |= 8;
            packetcount->udp++;
        }
    }
    else if (e_ntohs(pheaders->eth->eth_type) == 0x86dd)
    {
        pheaders->ip6h = (const ip6_hdr *)(sizeof(eth_hdr) + packet);
        packetcount->ipv6++;
        if (pheaders->ip6h->ip6_next == 58)
        {
            pheaders->icmph = (const icmp_hdr *)(sizeof(eth_hdr) + sizeof(ip6_hdr) + packet);
            flags |= 16;
            packetcount->icmp++;
        }
        else if (pheaders->ip6h->ip6_next == 6)
        {
            pheaders->tcph = (const tcp_hdr *)(sizeof(eth_hdr) + sizeof(ip6_hdr) + packet);
            flags |= 32;
            packetcount->tcp++;
        }
        else if (pheaders->ip6h->ip6_next == 17)
        {
            pheaders->udph = (const udp_hdr *)(sizeof(eth_hdr) + sizeof(ip6_hdr) + packet);
            flags |= 64;
            packetcount->udp++;
        }
    }
    return flags;
}

void checkrule(bit8_t flags) //0BBB BBBB 예약 iph6udp iph6tcp iph6icmp ip4hudp ip4htcp ip4hicmp arp
{
    int i, ismatched = 0;
    switch (flags)
    {
    case 1: // arp
        for (i = 0; i < count; i++)
        {
            if (strcmp(readrules[i]->ptc, "arp") && !(readrules[i]->ignore & 2)) // 0 이그노어 비트가 true인 경우 통과 경우: 1 무시 AND true=1인 경우
                continue;
            if (strcmp(readrules[i]->srcip, strip4(pheaders->arph->arp_src_ip)) && !(readrules[i]->ignore & 4))
                continue;
            if (strcmp(readrules[i]->dstip, strip4(pheaders->arph->arp_dst_ip)) && !(readrules[i]->ignore & 16))
                continue;
            rulecount->arp++;
            ismatched = 1;
            break;
        }
        if (ismatched)
        {
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n"); // 20 바이트
            print_eth();
            print_arp();
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
        }
        break;
    case 2: // icmpv4
        for (i = 0; i < count; i++)
        {
            if (strcmp(readrules[i]->ipver, "ipv4") && !(readrules[i]->ignore & 1))
                continue;
            if (strcmp(readrules[i]->ptc, "icmp") && !(readrules[i]->ignore & 2))
                continue;
            if (strcmp(readrules[i]->srcip, strip4(pheaders->ip4h->ip4_src_ip)) && !(readrules[i]->ignore & 4))
                continue;
            if (strcmp(readrules[i]->dstip, strip4(pheaders->ip4h->ip4_dst_ip)) && !(readrules[i]->ignore & 16))
                continue;
            rulecount->ipv4++;
            rulecount->icmp++;
            ismatched = 1;
            break;
        }
        if (ismatched)
        {
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n"); // 20 바이트
            print_eth();
            print_ipv4();
            print_icmp();
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
        }
        break;
    case 4: // tcpv4
        for (i = 0; i < count; i++)
        {
            if (strcmp(readrules[i]->ipver, "ipv4") && !(readrules[i]->ignore & 1))
                continue;
            if (strcmp(readrules[i]->ptc, "tcp") && !(readrules[i]->ignore & 2))
                continue;
            if (strcmp(readrules[i]->srcip, strip4(pheaders->ip4h->ip4_src_ip)) && !(readrules[i]->ignore & 4))
                continue;
            if ((atoi(readrules[i]->srcport) != e_ntohs(pheaders->tcph->tcp_src_port)) && !(readrules[i]->ignore & 8))
                continue;
            if (strcmp(readrules[i]->dstip, strip4(pheaders->ip4h->ip4_dst_ip)) && !(readrules[i]->ignore & 16))
                continue;
            if ((atoi(readrules[i]->dstport) != e_ntohs(pheaders->tcph->tcp_dst_port)) && !(readrules[i]->ignore & 32))
                continue;
            rulecount->ipv4++;
            rulecount->tcp++;
            ismatched = 1;
            break;
        }
        if (ismatched)
        {
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n"); // 20 바이트
            print_eth();
            print_ipv4();
            print_tcp();
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
        }
        break;
    case 8: // udpv4
        for (i = 0; i < count; i++)
        {
            if (strcmp(readrules[i]->ipver, "ipv4") && !(readrules[i]->ignore & 1))
                continue;
            if (strcmp(readrules[i]->ptc, "udp") && !(readrules[i]->ignore & 2))
                continue;
            if (strcmp(readrules[i]->srcip, strip4(pheaders->ip4h->ip4_src_ip)) && !(readrules[i]->ignore & 4))
                continue;
            if ((atoi(readrules[i]->srcport) != e_ntohs(pheaders->udph->udp_src_port)) && !(readrules[i]->ignore & 8))
                continue;
            if (strcmp(readrules[i]->dstip, strip4(pheaders->ip4h->ip4_dst_ip)) && !(readrules[i]->ignore & 16))
                continue;
            if ((atoi(readrules[i]->dstport) != e_ntohs(pheaders->udph->udp_dst_port)) && !(readrules[i]->ignore & 32))
                continue;
            rulecount->ipv4++;
            rulecount->udp++;
            ismatched = 1;
            break;
        }
        if (ismatched)
        {
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n"); // 20 바이트
            print_eth();
            print_ipv4();
            print_udp();
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
        }
        break;
    case 16: // icmpv6
        for (i = 0; i < count; i++)
        {
            if (strcmp(readrules[i]->ipver, "ipv6") && !(readrules[i]->ignore & 1))
                continue;
            if (strcmp(readrules[i]->ptc, "icmp") && !(readrules[i]->ignore & 2))
                continue;
            if (strcmp(readrules[i]->srcip, strip6(pheaders->ip6h->ip6_src_ip)) && !(readrules[i]->ignore & 4))
                continue;
            if (strcmp(readrules[i]->dstip, strip6(pheaders->ip6h->ip6_dst_ip)) && !(readrules[i]->ignore & 16))
                continue;
            rulecount->ipv6++;
            rulecount->icmp++;
            ismatched = 1;
            break;
        }
        if (ismatched)
        {
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n"); // 20 바이트
            print_eth();
            print_ipv6();
            print_icmp();
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
        }
        break;
    case 32: // tcpv6
        for (i = 0; i < count; i++)
        {
            if (strcmp(readrules[i]->ipver, "ipv6") && !(readrules[i]->ignore & 1))
                continue;
            if (strcmp(readrules[i]->ptc, "tcp") && !(readrules[i]->ignore & 2))
                continue;
            if (strcmp(readrules[i]->srcip, strip6(pheaders->ip6h->ip6_src_ip)) && !(readrules[i]->ignore & 4))
                continue;
            if ((atoi(readrules[i]->srcport) != e_ntohs(pheaders->tcph->tcp_src_port)) && !(readrules[i]->ignore & 8))
                continue;
            if (strcmp(readrules[i]->dstip, strip6(pheaders->ip6h->ip6_dst_ip)) && !(readrules[i]->ignore & 16))
                continue;
            if ((atoi(readrules[i]->dstport) != e_ntohs(pheaders->tcph->tcp_dst_port)) && !(readrules[i]->ignore & 32))
                continue;
            rulecount->ipv6++;
            rulecount->tcp++;
            ismatched = 1;
            break;
        }
        if (ismatched)
        {
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n"); // 20 바이트
            print_eth();
            print_ipv6();
            print_tcp();
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
        }
        break;
    case 64: // udpv6
        for (i = 0; i < count; i++)
        {
            if (strcmp(readrules[i]->ipver, "ipv6") && !(readrules[i]->ignore & 1))
                continue;
            if (strcmp(readrules[i]->ptc, "udp") && !(readrules[i]->ignore & 2))
                continue;
            if (strcmp(readrules[i]->srcip, strip6(pheaders->ip6h->ip6_src_ip)) && !(readrules[i]->ignore & 4))
                continue;
            if ((atoi(readrules[i]->srcport) != e_ntohs(pheaders->udph->udp_src_port)) && !(readrules[i]->ignore & 8))
                continue;
            if (strcmp(readrules[i]->dstip, strip6(pheaders->ip6h->ip6_dst_ip)) && !(readrules[i]->ignore & 16))
                continue;
            if ((atoi(readrules[i]->dstport) != e_ntohs(pheaders->udph->udp_dst_port)) && !(readrules[i]->ignore & 32))
                continue;
            rulecount->ipv6++;
            rulecount->udp++;
            ismatched = 1;
            break;
        }
        if (ismatched)
        {
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n"); // 20 바이트
            print_eth();
            print_ipv6();
            print_udp();
            fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
        }
        break;
    }
}

void printmatchresult()
{
    fprintf(stdout, "\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
    fprintf(stdout, "Packets: %20lld\n", packetcount->arp + packetcount->icmp + packetcount->ipv4 + packetcount->ipv6 + packetcount->tcp + packetcount->udp);
    fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
    fprintf(stdout, "Protocols:\n");
    fprintf(stdout, "\tARP: %16lld\n", packetcount->arp);
    fprintf(stdout, "\tIPv4: %15lld\n", packetcount->ipv4);
    fprintf(stdout, "\tIPv6: %15lld\n", packetcount->ipv6);
    fprintf(stdout, "\tICMP: %15lld\n", packetcount->icmp);
    fprintf(stdout, "\tTCP: %16lld\n", packetcount->tcp);
    fprintf(stdout, "\tUDP: %16lld\n", packetcount->udp);
    fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
    fprintf(stdout, "Protocol matched by Rules:\n");
    fprintf(stdout, "\tARP: %16lld\n", rulecount->arp);
    fprintf(stdout, "\tIPv4: %15lld\n", rulecount->ipv4);
    fprintf(stdout, "\tIPv6: %15lld\n", rulecount->ipv6);
    fprintf(stdout, "\tICMP: %15lld\n", rulecount->icmp);
    fprintf(stdout, "\tTCP: %16lld\n", rulecount->tcp);
    fprintf(stdout, "\tUDP: %16lld\n", rulecount->udp);
    fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
}

void freerules()
{
    int i;
    for (i = 0; i < count; i++)
    {
        free(readrules[i]->ipver);
        free(readrules[i]->ptc);
        free(readrules[i]->srcip);
        free(readrules[i]->dstip);
        free(readrules[i]->srcport);
        free(readrules[i]->dstport);
        free(readrules[i]);
    }
    free(readrules);
}

void print_eth(void)
{
    fprintf(stdout, "[ETH]\n");
    fprintf(stdout, "Source mac address: %s\n", strmac(pheaders->eth->eth_src_mac));
    fprintf(stdout, "Destination mac address: %s\n", strmac(pheaders->eth->eth_dst_mac));
}

void print_arp(void)
{
    fprintf(stdout, "[ARP]\n");
    fprintf(stdout, "Hardware type: %u\n", e_ntohs(pheaders->arph->arp_hard_type));
    fprintf(stdout, "Protocol type: 0x%04x\n", e_ntohs(pheaders->arph->arp_protocol));
    fprintf(stdout, "Hardware size: %u\n", pheaders->arph->arp_addr_len);
    fprintf(stdout, "Protocol size: %u\n", pheaders->arph->arp_protocol_len);
    fprintf(stdout, "Opcode: %u\n", e_ntohs(pheaders->arph->arp_opcode));
    fprintf(stdout, "Source mac address: %s\n", strmac(pheaders->arph->arp_src_mac));
    fprintf(stdout, "Source ip address: %s\n", strip4(pheaders->arph->arp_src_ip));
    fprintf(stdout, "Destination mac address: %s\n", strmac(pheaders->arph->arp_dst_mac));
    fprintf(stdout, "Destination ip address: %s\n", strip4(pheaders->arph->arp_dst_ip));
}

void print_icmp(void)
{
    fprintf(stdout, "[ICMP]\n");
    fprintf(stdout, "Type: %u\n", pheaders->icmph->icmp_type);
    fprintf(stdout, "Code: %u\n", pheaders->icmph->icmp_code);
    fprintf(stdout, "Checksum: 0x%04x\n", e_ntohs(pheaders->icmph->icmp_checksum));
}

void print_ipv4(void)
{
    fprintf(stdout, "[IPv4]\n");
    fprintf(stdout, "Version: %u\n", pheaders->ip4h->ip4_ver);
    fprintf(stdout, "Header length: %u\n", pheaders->ip4h->ip4_hdrlen * 4);
    fprintf(stdout, "Type of Service: 0x%02x\n", pheaders->ip4h->ip4_tos);
    fprintf(stdout, "Total Length: %u\n", e_ntohs(pheaders->ip4h->ip4_tot_len));
    fprintf(stdout, "Identification: 0x%04x\n", e_ntohs(pheaders->ip4h->ip4_id));
    fprintf(stdout, "Flags: 0x%04x\n", e_ntohs(pheaders->ip4h->ip4_frag_off) & 0xe000);
    fprintf(stdout, "Fragment offset: %u\n", e_ntohs(pheaders->ip4h->ip4_frag_off) & 0x1fff);
    fprintf(stdout, "Time to Live: %u\n", pheaders->ip4h->ip4_ttl);
    fprintf(stdout, "Protocol: %u\n", pheaders->ip4h->ip4_protocol);
    fprintf(stdout, "Header checksum: 0x%04x\n", e_ntohs(pheaders->ip4h->ip4_checksum));
    fprintf(stdout, "Source ip address: %s\n", strip4(pheaders->ip4h->ip4_src_ip));
    fprintf(stdout, "Destination ip address: %s\n", strip4(pheaders->ip4h->ip4_dst_ip));
}

void print_ipv6(void)
{
    fprintf(stdout, "[IPv6]\n");
    fprintf(stdout, "Version: %u\n", (e_ntohl(pheaders->ip6h->ip6_flow) & 0xF0000000) >> 28);
    fprintf(stdout, "Traffic class: 0x%02x\n", (e_ntohl(pheaders->ip6h->ip6_flow) & 0x0FF00000) >> 20);
    fprintf(stdout, "Flow Label: 0x%05x\n", e_ntohl(pheaders->ip6h->ip6_flow) & 0x000FFFFF);
    fprintf(stdout, "Payload length: %u\n", e_ntohs(pheaders->ip6h->ip6_pay_len));
    fprintf(stdout, "Next header: %u\n", pheaders->ip6h->ip6_next);
    fprintf(stdout, "Hop limit: %u\n", pheaders->ip6h->ip6_hop_limit);
    fprintf(stdout, "Source: %s\n", strip6(pheaders->ip6h->ip6_src_ip));
    fprintf(stdout, "Destination: %s\n", strip6(pheaders->ip6h->ip6_dst_ip));
}

void print_tcp(void)
{
    fprintf(stdout, "[TCP]\n");
    fprintf(stdout, "Source port: %u\n", e_ntohs(pheaders->tcph->tcp_src_port));
    fprintf(stdout, "Destination port: %u\n", e_ntohs(pheaders->tcph->tcp_dst_port));
    fprintf(stdout, "Sequence number: %u\n", e_ntohl(pheaders->tcph->tcp_seq));
    fprintf(stdout, "Acknowledgment number: %u\n", e_ntohl(pheaders->tcph->tcp_seq_ack));
    fprintf(stdout, "Header length: %u\n", pheaders->tcph->tcp_offset * 4);
    fprintf(stdout, "Flags: 0x%03x\n", pheaders->tcph->tcp_flags);
    fprintf(stdout, "Window size value: %u\n", e_ntohs(pheaders->tcph->tcp_window));
    fprintf(stdout, "Checksum: 0x%04x\n", e_ntohs(pheaders->tcph->tcp_checksum));
    fprintf(stdout, "Urgent pointer: %u\n", e_ntohs(pheaders->tcph->tcp_urgptr));
}

void print_udp(void)
{
    fprintf(stdout, "[UDP]\n");
    fprintf(stdout, "Source port: %u\n", e_ntohs(pheaders->udph->udp_src_port));
    fprintf(stdout, "Destination port: %u\n", e_ntohs(pheaders->udph->udp_dst_port));
    fprintf(stdout, "Length: %u\n", e_ntohs(pheaders->udph->udp_len));
    fprintf(stdout, "Checksum: 0x%04x\n", e_ntohs(pheaders->udph->udp_checksum));
}

void printmotd(const char *interface)
{
    fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
    fprintf(stdout, "C-NIDS Watcher opened interface: %s\n", interface);
    fprintf(stdout, "Ver: v1.0\n");
    fprintf(stdout, "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
}

/*
    char *ipver;
    char *ptc;
    char *srcip;
    char *srcport;
    char *dstip;
    char *dstport;
*/

/*
    1. 패킷 캡처 // 캡처할때 비트로 비교하고 포인터로 가리킨것을 룰 매치, 출력에 재 사용하여 성능향상
    2. 룰 매치 //룰 매치될 시 구조체에 카운트
    3. 출력
    4. 1. 반복
    5. 끝날때 매치된 횟수, 캡처한 패킷 횟수 출력
*/

/*
    fprintf(stdout, "------------------------------\n\n");
    if (e_ntohs(eth->eth_type) == 0x0806)
    { //arp
        arph = (const arp_hdr *)(sizeof(eth_hdr) + packet);


        fprintf(stdout, "[ARP]\n");
        fprintf(stdout, "Hardware type: %u\n", e_ntohs(arph->arp_hard_type));
        fprintf(stdout, "Protocol type: 0x%04x\n", e_ntohs(arph->arp_protocol));
        fprintf(stdout, "Hardware size: %u\n", arph->arp_addr_len);
        fprintf(stdout, "Protocol size: %u\n", arph->arp_protocol_len);
        fprintf(stdout, "Opcode: %u\n", e_ntohs(arph->arp_opcode));
        fprintf(stdout, "src mac addr: %s\n", strmac(arph->arp_src_mac));
        fprintf(stdout, "src ip addr: %s\n", strip4(arph->arp_src_ip));
        fprintf(stdout, "dst mac addr: %s\n", strmac(arph->arp_dst_mac));
        fprintf(stdout, "dst ip addr: %s\n", strip4(arph->arp_dst_ip));
    }
    else if (e_ntohs(eth->eth_type) == 0x0800)
    { // ipv4
        ip4h = (const ip4_hdr *)(sizeof(eth_hdr) + packet);

        fprintf(stdout, "[IPv4]\n");
        fprintf(stdout, "Version: %u\n", ip4h->ip4_ver);
        fprintf(stdout, "Header length: %u\n", ip4h->ip4_hdrlen * 4);
        fprintf(stdout, "Type of Service: 0x%02x\n", ip4h->ip4_tos);
        fprintf(stdout, "Total Length: %u\n", e_ntohs(ip4h->ip4_tot_len));
        fprintf(stdout, "Identification: 0x%04x\n", e_ntohs(ip4h->ip4_id));
        fprintf(stdout, "Flags: 0x%04x\n", e_ntohs(ip4h->ip4_frag_off) & 0xe000);
        fprintf(stdout, "Fragment offset: %u\n", e_ntohs(ip4h->ip4_frag_off) & 0x1fff);
        fprintf(stdout, "Time to Live: %u\n", ip4h->ip4_ttl);
        fprintf(stdout, "Protocol: %u\n", ip4h->ip4_protocol);
        fprintf(stdout, "Header checksum: 0x%04x\n", e_ntohs(ip4h->ip4_checksum));
        fprintf(stdout, "src: %s\n", strip4(ip4h->ip4_src_ip));
        fprintf(stdout, "dst: %s\n", strip4(ip4h->ip4_dst_ip));

        if(ip4h->ip4_protocol == 1){
            icmph = (const icmp_hdr*)(sizeof(eth_hdr) + (ip4h->ip4_hdrlen*4) + packet);
        
            fprintf(stdout, "[ICMP]\n");
            fprintf(stdout, "Type: %u\n", icmph->icmp_type);
            fprintf(stdout, "Code: %u\n", icmph->icmp_code);
            fprintf(stdout, "Checksum: 0x%04x\n", e_ntohs(icmph->icmp_checksum));
            fprintf(stdout, "Identifier (BE): %u (0x%04x)\n", e_ntohs(icmph->icmp_id), e_ntohs(icmph->icmp_id));
            fprintf(stdout, "Identifier (LE): %u (0x%04x)\n", icmph->icmp_id, icmph->icmp_id);
            fprintf(stdout, "Sequence number (BE): %u (0x%04x)\n", e_ntohs(icmph->icmp_seq), e_ntohs(icmph->icmp_seq));
            fprintf(stdout, "Sequence number (LE): %u (0x%04x)\n", icmph->icmp_seq, icmph->icmp_seq);
            fprintf(stdout, "data: 0x%08x\n", e_ntohl(icmph->data));
        }else if (ip4h->ip4_protocol == 6)
        { // tcp
            tcph = (const tcp_hdr *)(sizeof(eth_hdr) + (ip4h->ip4_hdrlen*4) + packet);

            fprintf(stdout, "[TCP]\n");
            fprintf(stdout, "Source port: %u\n", e_ntohs(tcph->tcp_src_port));
            fprintf(stdout, "Destination port: %u\n", e_ntohs(tcph->tcp_dst_port));
            fprintf(stdout, "Sequence number: %u\n", e_ntohl(tcph->tcp_seq));
            fprintf(stdout, "Acknowledgment number: %u\n", e_ntohl(tcph->tcp_seq_ack));
            fprintf(stdout, "Header length: %u\n", tcph->tcp_offset*4);
            fprintf(stdout, "Flags: 0x%03x\n", tcph->tcp_flags);
            fprintf(stdout, "Window size value: %u\n", e_ntohs(tcph->tcp_window));
            fprintf(stdout, "Checksum: 0x%04x\n", e_ntohs(tcph->tcp_checksum));
            fprintf(stdout, "Urgent pointer: %u\n", e_ntohs(tcph->tcp_urgptr));
        }
        else if (ip4h->ip4_protocol == 17)
        { // udp
            udph = (const udp_hdr *)(sizeof(eth_hdr) + (ip4h->ip4_hdrlen*4) + packet);
            
            fprintf(stdout, "[UDP]\n");
            fprintf(stdout, "Source port: %u\n", e_ntohs(udph->udp_src_port));
            fprintf(stdout, "Destination port: %u\n", e_ntohs(udph->udp_dst_port));
            fprintf(stdout, "Length: %u\n", e_ntohs(udph->udp_len));
            fprintf(stdout, "Checksum: 0x%04x\n", e_ntohs(udph->udp_checksum));
        }
    }
    else if (e_ntohs(eth->eth_type) == 0x86dd)
    { // ipv6
        ip6h = (const ip6_hdr *)(sizeof(eth_hdr) + packet);

        fprintf(stdout, "[IPv6]\n");
        fprintf(stdout, "Version: %u\n", (e_ntohl(ip6h->ip6_flow) & 0xF0000000) >> 28);
        fprintf(stdout, "Traffic class: 0x%02x\n", (e_ntohl(ip6h->ip6_flow) & 0x0FF00000) >> 20);
        fprintf(stdout, "Flow Label: 0x%05x\n", e_ntohl(ip6h->ip6_flow) & 0x000FFFFF);
        fprintf(stdout, "Payload length: %u\n", e_ntohs(ip6h->ip6_pay_len));
        fprintf(stdout, "Next header: %u\n", ip6h->ip6_next);
        fprintf(stdout, "Hop limit: %u\n", ip6h->ip6_hop_limit);
        fprintf(stdout, "Source: %s\n", strip6(ip6h->ip6_src_ip));
        fprintf(stdout, "Destination: %s\n", strip6(ip6h->ip6_dst_ip));

        if (ip6h->ip6_next == 6)
        { // tcp
            tcph = (const tcp_hdr *)(sizeof(eth_hdr) + sizeof(ip6_hdr) + packet);
        
            fprintf(stdout, "[TCP]\n");
            fprintf(stdout, "Source port: %u\n", e_ntohs(tcph->tcp_src_port));
            fprintf(stdout, "Destination port: %u\n", e_ntohs(tcph->tcp_dst_port));
            fprintf(stdout, "Sequence number: %u\n", e_ntohl(tcph->tcp_seq));
            fprintf(stdout, "Acknowledgment number: %u\n", e_ntohl(tcph->tcp_seq_ack));
            fprintf(stdout, "Header length: %u\n", tcph->tcp_offset*4);
            fprintf(stdout, "Flags: 0x%03x\n", tcph->tcp_flags);
            fprintf(stdout, "Window size value: %u\n", e_ntohs(tcph->tcp_window));
            fprintf(stdout, "Checksum: 0x%04x\n", e_ntohs(tcph->tcp_checksum));
            fprintf(stdout, "Urgent pointer: %u\n", e_ntohs(tcph->tcp_urgptr));
        }
        else if (ip6h->ip6_next == 17)
        { // udp
            udph = (const udp_hdr *)(sizeof(eth_hdr) + sizeof(ip6_hdr) + packet);
        
            fprintf(stdout, "[UDP]\n");
            fprintf(stdout, "Source port: %u\n", e_ntohs(udph->udp_src_port));
            fprintf(stdout, "Destination port: %u\n", e_ntohs(udph->udp_dst_port));
            fprintf(stdout, "Length: %u\n", e_ntohs(udph->udp_len));
            fprintf(stdout, "Checksum: 0x%04x\n", e_ntohs(udph->udp_checksum));
        }
    }

    fprintf(stdout, "------------------------------\n\n");
*/