사용법
=============
1. ./vpn-serv (define 부분의 ip, port 확인 필요!!)
2. sudo ./vpn_clnt dum0
아래서부터는 클라이언트
3. sudo ip link add dum0 type dummy; sudo ifconfig dum0 up; sudo dhclient -i dum0;
4.  sudo ./vpn_clnt dum0 (define 부분의 ip, port 확인 필요!!)

코드 동작
-------------
클라이언트의 dum0 더미 인터페이스에서 dhcp discover 패킷이 발생되면
dhcp discover 패킷을 tcp통신으로 서버에게 보냅니다.
이를 받은 서버는 dhcp discover를 서버가 위치한 사설 대역에 브로드캐스트를 하게 됩니다.
