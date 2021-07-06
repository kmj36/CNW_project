#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 8192

struct Ether{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
};

struct Ip{
	uint32_t ip_src;
	uint32_t ip_dst;
};

struct Pro{
	uint8_t protocol;
};

struct ip_h{
	uint8_t ip_hl : 4;
};

struct Tcp{
	uint16_t s_port;
	uint16_t d_port;
};

void print_mac(uint8_t *mac) {
	int i;
	for (i = 0; i < 5; i++) {
		printf("%02x:", mac[i]);
	}
	printf("%02x", mac[5]);
}

uint16_t ntohs(uint16_t i) {
	uint16_t a = (i & 0x00ff) << 8;
	uint16_t b = (i & 0xff00) >> 8;
	return a | b;
}

int main(int argc, char **argv)
{
	if(argc != 2) {
		printf("Usage: sudo %s <interface>", argv[0]);
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * handle = NULL;
	handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 0, 512, errbuf);
	
	if(handle == NULL){
		printf("can't not open");
		return -1;
	}

	printf("%s Opened\n", argv[1]);

	struct pcap_pkthdr * header;
	struct Ip* iph;
	struct Tcp* tcph;
	struct ip_h* iphl;
	struct Pro* pt;
	const uint8_t *packet;
	int res;

	while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if(res == 0) continue;
		struct Ether * pk = (struct Ether *)packet;
		pk->type = ntohs(pk->type);
		iphl = (struct ip_h*)(packet + sizeof(struct Ether));
		iph = (struct Ip*)(packet + sizeof(struct Ether)+12);
		tcph = (struct Tcp*)(packet + 14 + iphl->ip_hl*4);
		pt = (struct Pro*)(packet + sizeof(struct Ether)+ 9);
		
		if(pt->protocol == 1)
			printf("protocol: ICMP\n");
		else if(pt->protocol == 2)
			printf("protocol: IGMP\n");
		else if(pt->protocol == 6)
			printf("protocol: TCP\n");
		else if(pt->protocol == 17)
			printf("protocol: UDP\n");

		printf("src: %d.%d.%d.%d port: %6d\n", (iph->ip_src & 0xFF), (iph->ip_src & 0xFF00) >> 8, (iph->ip_src & 0xFF0000) >> 16, (iph->ip_src & 0xFF000000) >> 24, ntohs(tcph->s_port));
		printf("dst: %d.%d.%d.%d port: %6d\n", (iph->ip_dst & 0xFF), (iph->ip_dst & 0xFF00) >> 8, (iph->ip_dst & 0xFF0000) >> 16, (iph->ip_dst & 0xFF000000) >> 24, ntohs(tcph->d_port));

		if(pk->type == 0x0800)
			printf("Type: ipv4\n\n");
		else if(pk->type == 0x86dd)
			printf("Type: ipv6\n\n");
		else if(pk->type == 0x0806)
			printf("Type: ARP\n\n");
		else
			printf("Type: %04x\n\n", pk->type);
	}

	pcap_close(handle);
	return 0;
}
