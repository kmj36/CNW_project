# CNW_project

The new linux C-language NIDS



# Beta v1.0

빌드: ./make.sh

사용법: sudo ./CNW_IDS \<interface\>

규칙 파일: rule.ini
  ```
  사용가능 ip: ipv4, ipv6
  사용가능 프로토콜: arp(port 무시), tcp, udp, icmp(port 무시)
  탐지규칙: ipv4 tcp [srcip] [srcport] > [dstip] [dstport]
  ```

![Screenshot from 2021-09-10 14-56-50](https://user-images.githubusercontent.com/66502982/132806783-797209e6-133e-4d91-b9f2-1a3acae10942.png)
