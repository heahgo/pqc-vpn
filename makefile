vpn_serv : vpn_serv.cpp vpn_clnt
	g++ -o vpn_serv vpn_serv.cpp -lpcap

vpn_clnt : vpn_clnt.cpp
	g++ -o vpn_clnt vpn_clnt.cpp -lpcap

clean : 
	rm vpn_serv vpn_clnt