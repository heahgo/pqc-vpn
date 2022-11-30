#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <sys/socket.h>
#include "dhcp/dhcp.h"
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>

#define IP "192.168.35.65" // server ip add
#define PORT 12345         // server port number

void printPacket(struct ether_header *eth, struct ip *iphdr, struct udphdr *udp)
{
    printf("\nsrc mac: %02x:%02x:%02x:%02x:%02x:%02x   ", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x \n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("src ip : %s     ", inet_ntoa(iphdr->ip_src));
    printf("dst ip : %s \n", inet_ntoa(iphdr->ip_dst));
    printf("src port : %hu   dst port : %hu\n\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
}

void errHandle(const char *file, const char *func, int line)
{
    printf("filename : %s,    function : %s,    line : %d\n", file, func, line);
    printf("error: %s\n", strerror(errno));
    exit(0);
}

int main()
{
    int serv_sock;
    struct sockaddr_in serv_addr;

    serv_sock = socket(AF_INET, SOCK_STREAM, 0); // server socket tcp
    if (serv_sock < 0)
        errHandle(__FILE__, __FUNCTION__, __LINE__);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IP);
    serv_addr.sin_port = htons(PORT);

    int res = bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)); // bind
    if (res == -1)
        errHandle(__FILE__, __FUNCTION__, __LINE__);

    int res2 = listen(serv_sock, 5); // listen
    if (res2 == -1)
        errHandle(__FILE__, __FUNCTION__, __LINE__);

    int clnt_sock;
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;
    clnt_addr_size = sizeof(clnt_addr);

    clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1)
        errHandle(__FILE__, __FUNCTION__, __LINE__);

    int broad_sock;
    int bcast = 1;
    struct sockaddr_in broad_addr;
    broad_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (broad_sock < 0)
        errHandle(__FILE__, __FUNCTION__, __LINE__);

    memset(&broad_addr, 0, sizeof(broad_addr));
    broad_addr.sin_family = AF_INET;
    broad_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST); //브로드캐스트
    broad_addr.sin_port = 67;   //dhcp server port
    setsockopt(broad_sock, SOL_SOCKET, SO_BROADCAST, (char *)&bcast, sizeof(bcast)); //브로드캐스트 옵션 이거 설정안하면 권한 오류 남

    while (true)
    {
        uint8_t packet[512] = {
            0,
        };
        int res3 = read(clnt_sock, packet, 512);
        if (res3 <= 0)
            errHandle(__FILE__, __FUNCTION__, __LINE__);

        // eth
        struct ether_header *eth = (struct ether_header *)packet;
        // ip
        struct ip *iphdr = (struct ip *)(packet + sizeof(struct ether_header));
        uint16_t ip_total_len = ntohs(iphdr->ip_len);
        uint8_t ip_head_len = (iphdr->ip_hl) * 4;
        // udp
        struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_head_len);
        uint8_t udp_head_len = 8;
        // dhcp
        struct dhcp *dphdr = (struct dhcp *)(packet + sizeof(struct ether_header) + ip_head_len + udp_head_len);

        // dhcp packet 0x800 : ipv4, 17 : udp, 68 : dhcp client
        if (ntohs(eth->ether_type) != 0x800 || iphdr->ip_p != 17 || ntohs(udp->uh_sport) != 68)
            continue;

        if (dphdr->dp_options[4] != 53 || dphdr->dp_options[6] != DHCPDISCOVER) // dhcp discover인지 확인
        {
            continue;
        }
        
        // send packet
        int res4 = sendto(broad_sock, packet + sizeof(struct ether_header), ip_total_len, 0,
                          (const struct sockaddr *)&broad_addr, sizeof(broad_addr));
        if (res4 < 0)
            errHandle(__FILE__, __FUNCTION__, __LINE__);

        printPacket(eth, iphdr, udp);
        printf("this packet dhcp discover!!\nxid : %x\n", ntohl(dphdr->dp_xid));
    }
    printf("close\n");
    close(serv_sock);
}
