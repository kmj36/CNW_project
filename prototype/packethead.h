#pragma once
typedef unsigned char bit8_t;
typedef unsigned short bit16_t;
typedef unsigned int bit32_t;
typedef unsigned long long bit64_t;

/*
    이더넷 헤더
*/

#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN 14

typedef struct ethernet_header { 
    bit8_t eth_dst_mac[ETH_ADDR_LEN]; // 도착지 맥주소
    bit8_t eth_src_mac[ETH_ADDR_LEN]; // 출발지 맥주소
    bit16_t eth_type; // 패킷 타입
}eth_hdr;

/*
    IP 헤더
*/

#define IP4_ADDR_LEN 4
#define IP6_ADDR_LEN 8

typedef struct ipv4_header { 
#if __BYTE_ORDER == __LITTLE_ENDIAN // 리틀엔디안
    bit8_t ip4_hdrlen : 4; // 헤더 길이
    bit8_t ip4_ver : 4; // 버전
#elif __BYTE_ORDER == __BIG_ENDIAN // 빅엔디안
    bit8_t ip4_ver : 4; // 버전
    bit8_t ip4_hdrlen : 4; // 헤더 길이
#endif
    bit8_t ip4_tos; // 서비스 타입
    bit16_t ip4_tot_len; // 전체 길이
    bit16_t ip4_id; // 확인 숫자
    bit16_t ip4_frag_off; // 플래그와 분할 오프셋
    bit8_t ip4_ttl; // 생존 타임
    bit8_t ip4_protocol; // 프로토콜 타입
    bit16_t ip4_checksum; // 체크섬
    bit8_t ip4_src_ip[IP4_ADDR_LEN]; // 출발지 ip
    bit8_t ip4_dst_ip[IP4_ADDR_LEN]; // 도착지 ip
}ip4_hdr;

typedef struct ipv6_header {
    bit32_t ip6_flow; /*4bit 버전, 8비트 트래픽 클래스, 20비트 플로우 라벨*/
    bit16_t ip6_pay_len; // 페이로드 길이
    bit8_t ip6_next; // 다음 헤더
    bit8_t ip6_hop_limit; // ipv6 TTL
    bit16_t ip6_src_ip[IP6_ADDR_LEN]; // 출발지 ip6
    bit16_t ip6_dst_ip[IP6_ADDR_LEN]; // 도착지 ip6
}ip6_hdr;

/*
    ARP 헤더
*/

#define ARP_MAC_LEN 6
#define ARP_IP_LEN 4

typedef struct arp_header {
    bit16_t arp_hard_type; // 하드웨어 타입
    bit16_t arp_protocol; // 프로토콜
    bit8_t arp_addr_len; // MAC 주소 길이
    bit8_t arp_protocol_len; // 프로토콜 길이
    bit16_t arp_opcode; // 명령코드
    bit8_t arp_src_mac[ARP_MAC_LEN]; // 출발지 MAC
    bit8_t arp_src_ip[ARP_IP_LEN]; // 출발지 IP
    bit8_t arp_dst_mac[ARP_MAC_LEN]; // 도착지 MAC
    bit8_t arp_dst_ip[ARP_IP_LEN]; // 도착지 IP
}arp_hdr;

/*
    ICMP 헤더
*/

typedef struct icmp_header {
    bit8_t icmp_type; // ICMP 타입
    bit8_t icmp_code; // 코드
    bit16_t icmp_checksum; // 체크섬
}icmp_hdr;

/*
    TCP, UDP 헤더
*/

typedef struct tcp_header { 
    bit16_t tcp_src_port; // 출발지 포트
    bit16_t tcp_dst_port; // 도착지 포트
    bit32_t tcp_seq; // 순서
    bit32_t tcp_seq_ack; // 승인
#if __BYTE_ORDER == __LITTLE_ENDIAN
    bit8_t tcp_rsvd: 4;
    bit8_t tcp_offset: 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    bit8_t tcp_offset: 4;
    bit8_t tcp_rsvd: 4;
#endif
    bit8_t tcp_flags;
#define TCP_FIN 0X01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
    bit16_t tcp_window; // 윈도우 사이즈
    bit16_t tcp_checksum; //체크섬
    bit16_t tcp_urgptr; // 긴급포인터
}tcp_hdr;

typedef struct udp_header { 
    bit16_t udp_src_port; // 출발지 포트
    bit16_t udp_dst_port; // 도착지 포트
    bit16_t udp_len; // 길이
    bit16_t udp_checksum; // UDP 체크섬
}udp_hdr;