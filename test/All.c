#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 8192

typedef struct Ether{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
}Eth;

typedef struct IP{
	uint8_t Version : 4;
	uint8_t IHL : 4;
	uint8_t TOS;
	uint16_t Total_len;
	uint16_t Identification;
	uint8_t Flags : 3;
	uint16_t Fragment_Off : 13;
	uint8_t TTL;
	uint8_t Protocol;
	uint16_t HC;
	uint8_t Srcadd[4];
	uint8_t Dstadd[4];
	uint32_t IPoption;
}ipv4;

typedef struct TCP{
	uint16_t srcport;
	uint16_t dstport;
	uint32_t seqnum;
	uint32_t acknum;
	uint8_t Offset : 4;
	uint8_t Reserved : 4;
	uint8_t Flag;
	uint16_t Window;
	uint16_t Checksum;
	uint16_t UrgPo;
	uint32_t tcpop;
}tcp;

typedef struct UDP{
	uint16_t srcport;
	uint16_t dstport;
	uint16_t length;
	uint16_t checksum;
}udp;

void print_mac(uint8_t *mac) {
	int i;
	for (i = 0; i < 5; i++)
		printf("%02x:", mac[i]);
	printf("%02x", mac[5]);
}

void print_ip(uint8_t *ip) {
	printf("%3d.", ip[0]);
	printf("%3d.", ip[1]);
	printf("%3d.", ip[2]);
	printf("%3d", ip[3]);
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
		printf("can't open %s", argv[1]);
		return -1;
	}

	printf("%s Opened\n", argv[1]);

	struct pcap_pkthdr * header;
	const uint8_t *packet;
	Eth *Ether;
	ipv4 *IP;
	tcp *TCP;
	udp *UDP;
	int res;

	while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if(res == 0) continue;
		Ether = (Eth*)packet;
		Ether->type = ntohs(Ether->type);
		IP = (ipv4*)(packet + sizeof(Ether));
		TCP = (tcp*)(packet + sizeof(Ether) + sizeof(ipv4));
		UDP = (udp*)(packet + sizeof(Ether) + sizeof(ipv4) + sizeof(tcp));
		
		print_ip(IP->Srcadd);
		printf(" -> ");
		print_ip(IP->Dstadd);
		printf("\n");
	}

	pcap_close(handle);
	return 0;
}
