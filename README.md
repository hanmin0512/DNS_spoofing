# DNS_spoofing
- DNS Spoofing은 사전에 ARP Spoofing이 성공된 상태에서 해야한다.
- <a href=""> ARP Spoofing 학습하기 </a>
- 실행환경은 KALI Linux이다.

## DNS Spoofing 개념
- DNS 동작 방식을 악용하여 피해자(victim)가 정상 웹사이트가 아닌 해커의 파밍사이트로 유도하는 기술
- 피해자의 패킷을 가로채서 변조시켜 피해자에게 전송
- <a href = ""> DNS 개념 학습하기 </a>

## DNS Spoofing 원리 (ARP Spoofing이 성공한 상태)
- ARP Cache Table이 poisoning된상태의 피해자(victim)가 웹 브라우저를 통해 특정 사이트로 이동한다(facebook, instagram ...)
- victim은 DNS server에 사이트 url에 매칭되는 웹 사이트 ip주소를 요청한다.
- DNS server에 패킷을 보내려면 같은 네트워크안에 Gateway를 거쳐야한다.
- 하지만 피해자의 ARP Cache Table은 Gateway의 MAC주소는 malicious의 MAC주소로 변조된 상태이다.
- 그렇기에 DNS 요청 패킷은 malicious에게 전송된다.
- malicious는 자신이 설정한 특정 url이 아니면 정상통신을 위해 ip forwarding을 해준다.
- malicious가 설정한 특정 사이트의 reply 패킷이라면 DNSRR패킷의 rdata 부분에 malicious의 파밍 사이트의 웹 서버 ip를 기입한다.
- 피해자는 자신이 요청한 사이트와 똑같은 화면을 보고 자신의 정보를 기입한다.
- 기입한 정보는 malicious에게 전달 된다.

## 구현 환경
- python
- scapy

