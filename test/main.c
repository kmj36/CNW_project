#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 8192

struct Ether{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
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

int main(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * handle = NULL;
	handle = pcap_open_live("ens33", MAX_PACKET_SIZE, 0, 512, errbuf);
	
	if(handle == NULL){
		printf("can't not open");
		return -1;
	}

	printf("ens33 Opened\n");

	struct pcap_pkthdr * header;
	const uint8_t *packet;
	int res;

	while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if(res == 0) continue;
		struct Ether * pk = (struct Ether *)packet;
		pk->type = ntohs(pk->type);

		print_mac(pk->src);
		printf(" -> ");
		print_mac(pk->dst);

		printf("\t");
		printf("%04x", pk->type);
		printf("\n");
	}

	pcap_close(handle);
	return 0;
}
