사용법
=============
1. ./vpn-serv (define 부분의 ip, port 확인 필요!!)
2. sudo ./vpn_clnt dum0
아래서부터는 클라이언트
3. sudo ip link add dum0 type dummy; sudo ifconfig dum0 up; sudo dhclient -i dum0;
4.  sudo ./vpn_clnt dum0 (define 부분의 ip, port 확인 필요!!)

위를 실행하면 클라이언트 dum0에서 발생되는 dhcp discover 패킷이 tcp통신으로 서버에 전달 됨.
서버는 받은 dhcp discover 패킷을 브로드캐스트로 쏨.
근데 sendto함수는 동작하는데 정작 wireshark에는 안잡힘

할말
-------------
이거 dhcp는 제대로 받아오는거 같아요.
if문으로 dhcp인지 확인하는 부분 넣었는데 잘 통과합니다ㅠㅠ..
아마 wireshark에서 안보이는거일수도,,, 

UDP 브로드캐스트는 집에서 인터넷 연결하고 하니까 잘 됨,,
인터넷 문제였던듯