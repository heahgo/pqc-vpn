#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include "dhcp/dhcp.h"
#include <errno.h>
#include <net/ethernet.h>
#include <pcap.h>

#define IP "192.168.35.65"
#define PORT 12345

void usage()
{
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

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

int main(int argc, char *argv[])
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    int clnt_sock;
    struct sockaddr_in serv_addr;

    clnt_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (clnt_sock < 0)
        errHandle(__FILE__, __FUNCTION__, __LINE__);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IP);
    serv_addr.sin_port = htons(PORT);

    if (connect(clnt_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
        errHandle(__FILE__, __FUNCTION__, __LINE__);

    while (true)
    {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

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

        // option
        // Magic Cookie (dp_optinons[0] ~[3]) = { 0x63, 0x82, 0x53, 0x63 }
        // dhcp discover
        if (dphdr->dp_options[4] != 53 || dphdr->dp_options[6] != DHCPDISCOVER) // dhcp discover인지 확인
        {
            continue;
        }

        getchar();
        int res2 = write(clnt_sock, packet, sizeof(struct ether_header) + ip_total_len); // 캡쳐한 dhcp패킷 보냄
        if (res2 < 0)
            errHandle(__FILE__, __FUNCTION__, __LINE__);

        printPacket(eth, iphdr, udp);
        printf("this packet dhcp discover!!\nxid : %x\n", ntohl(dphdr->dp_xid));
    }
    pcap_close(pcap);
}