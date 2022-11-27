#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <sys/socket.h>
#include "dhcp/dhcp.h"
#include <netinet/tcp.h>
#include <unistd.h>
#include <pcap.h>

#define print_log() printf("filename : %s,    function : %s,    line : %d\n", __FILE__, __FUNCTION__, __LINE__)
#define IP "192.168.0.3"
#define PORT 12345

typedef struct ether_header
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} ETH_HEAD;

void printPacket(ETH_HEAD *eth, struct ip *iphdr, struct udphdr *udp)
{
    printf("\nsrc mac: %02x:%02x:%02x:%02x:%02x:%02x   ", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x \n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
    printf("src ip : %s     ", inet_ntoa(iphdr->ip_src));
    printf("dst ip : %s \n", inet_ntoa(iphdr->ip_dst));
    printf("src port : %hu   dst port : %hu\n\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
}

int main()
{
    int serv_sock;
    int clnt_sock;
    int broad_sock;

    struct sockaddr_in serv_addr;
    struct sockaddr_in clnt_addr;
    struct sockaddr_in broad_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(AF_INET, SOCK_STREAM, 0);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IP);
    serv_addr.sin_port = htons(PORT);

    int res2 = bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (res2 == -1)
    {
        print_log();
        strerror(errno);
        exit(0);
    }
    int res3 = listen(serv_sock, 5);
    if (res3 == -1)
    {
        print_log();
        strerror(errno);
        exit(0);
    }
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1)
    {
        print_log();
        strerror(errno);
        exit(0);
    }

    while (true)
    {
        uint8_t packet[512];
        int res = read(clnt_sock, packet, 512);
        if (res <= 0)
        {
            break;
        }

        // eth
        // ETH_HEAD *eth = (ETH_HEAD *)packet;
        // ip
        struct ip *iphdr = (struct ip *)(packet + sizeof(ETH_HEAD));
        uint16_t ip_total_len = ntohs(iphdr->ip_len);
        uint8_t ip_head_len = (iphdr->ip_hl) * 4;
        // udp
        struct udphdr *udp = (struct udphdr *)(packet + sizeof(ETH_HEAD) + ip_head_len);
        uint8_t udp_head_len = 8;
        // dhcp
        struct dhcp *dphdr = (struct dhcp *)(packet + sizeof(ETH_HEAD) + ip_head_len + udp_head_len);
       
        int broad_sock;
        int bcast = 1;
        broad_sock = socket(AF_INET, SOCK_DGRAM, 0);    // udp로 보내면 잘되는데 rawsock으로 하면 브로드캐스트가 안됨, clnt에서 dhcp패킷을 이상하게 보낸거일수도?
        // broad_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        setsockopt( broad_sock, SOL_SOCKET, SO_BROADCAST, (char*)&bcast, sizeof(bcast) );   //브로드캐스트 옵션
        // setsockopt(broad_sock, IPPROTO_IP, IP_HDRINCL, (void *)&bcast, sizeof(bcast));
        memset(&serv_addr, 0, sizeof(serv_addr));
        broad_addr.sin_family = AF_INET;
        broad_addr.sin_addr.s_addr = htonl( INADDR_BROADCAST );
        broad_addr.sin_port = htons(udp->uh_sport);
        sendto(broad_sock, packet, sizeof(ETH_HEAD) + ip_total_len, 0, (struct sockaddr *)&broad_addr, sizeof(broad_addr));
        printf("sendto\n");
        // write(clnt_sock, packet, sizeof(ETH_HEAD) + ip_total_len);
    }
    printf("close\n");
    close(serv_sock);
}
