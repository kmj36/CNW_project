# CNW_project
The new linux C-language NIDS

# 언어
<img src="https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white"/>

# 필요 라이브러리

필요 라이브러리: libpcap
컴파일: gcc -o CNW_IDS CNW_IDS.c packetElements.c -l pcap

# 설명
C언어로 개발한 네트워크 기반 칩입 탐지 시스템입니다.
패킷을 받으면 패킷을 캡처하여 규칙파일 기반으로 검사 후 터미널에 출력 및 통계를 매깁니다.

추후 라이브러리: libcurl 으로 이메일 전송을 구현하여 규칙파일에 규칙을 추가 및
규칙에 맞으면 설정한 이메일로 전송하는 기능을 추가할 것입니다.

# 베타 v1.1

빌드: ./make.sh

사용법: sudo ./CNW_IDS \<interface\>

규칙 파일: rule.ini
  ```
  사용가능 ip: ipv4, ipv6
  사용가능 프로토콜: arp(port 무시), tcp, udp, icmp(port 무시)
  탐지규칙: [ip version] [protocol] [srcip] [srcport] > [dstip] [dstport]
  
  탐지규칙 예: ipv4 tcp 0.0.0.0 0 > 127.0.0.1 443
  any 규칙:
      ipv4: any any 0.0.0.0 0 > 0.0.0.0 0
      ipv6: any any :: 0 > :: 0
  ```

![Screenshot from 2021-09-10 14-56-50](https://user-images.githubusercontent.com/66502982/132806783-797209e6-133e-4d91-b9f2-1a3acae10942.png)
