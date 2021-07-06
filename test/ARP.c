#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 8192

struct Ether{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
};

struct ARP{
	uint16_t hwtype;
	uint16_t ptype;
	uint8_t maclen;
	uint8_t addlen;
	uint16_t opcode;
	uint8_t srcmac[6];
	uint8_t srcip[4];
	uint8_t dstmac[6];
	uint8_t dstip[4];
};

void print_ip(uint8_t *ip) {
	printf("%3d.%3d.%3d.%3d", ip[0], ip[1], ip[3], ip[4]);
}


void print_mac(uint8_t *mac) {
	int i;
	for (i = 0; i < 6; i++) {
		if(i == 5)
			printf("%02x", mac[i]);
		else
			printf("%02x:", mac[i]);
	}
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
	handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 0, 512, errbuf); // network interface monitering mode open
	
	if(handle == NULL){
		printf("can't not open %s please check %s interface.", argv[1], argv[1]);
		return -1;
	}

	printf("%s Opened\n", argv[1]);

	struct pcap_pkthdr* header;
	struct ARP* arph;
	struct Ether* eth;

	const uint8_t* packet;
	int res;

	while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if(res == 0) continue;
		eth = (struct Ether*)packet;
		eth->type = ntohs(eth->type);
		if(eth->type == 0x0806)
		{
			arph = (struct ARP*)(packet + sizeof(struct Ether));
			printf("[ARP]\n");
			printf("Src mac: "); print_mac(arph->srcmac);
			printf(" Snd ip: "); print_ip(arph->srcip);
			printf(" -> ");
			printf("Dst mac: "); print_mac(arph->dstmac);
			printf(" Tar ip: "); print_ip(arph->dstip);
			printf("\n");
		}
	}

	pcap_close(handle);
	return 0;
}
