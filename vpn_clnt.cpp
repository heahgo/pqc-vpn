#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include "dhcp/dhcp.h"
#include <netinet/tcp.h>
#include <unistd.h>
#include <pcap.h>

typedef struct ether_header
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} ETH_HEAD;

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

void printPacket(ETH_HEAD *eth, struct ip *iphdr, struct udphdr *udp)
{
    printf("\nsrc mac: %02x:%02x:%02x:%02x:%02x:%02x   ", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x \n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
    printf("src ip : %s     ", inet_ntoa(iphdr->ip_src));
    printf("dst ip : %s \n", inet_ntoa(iphdr->ip_dst));
    printf("src port : %hu   dst port : %hu\n\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
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

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(3000);

    if (connect(clnt_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
        return 0;

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
        ETH_HEAD *eth = (ETH_HEAD *)packet;
        // ip
        struct ip *iphdr = (struct ip *)(packet + sizeof(ETH_HEAD));           
        uint16_t ip_total_len = ntohs(iphdr->ip_len);
        uint8_t ip_head_len = (iphdr->ip_hl) * 4;
        // udp
        struct udphdr *udp = (struct udphdr *)(packet + sizeof(ETH_HEAD) + ip_head_len);
        uint8_t udp_head_len = 8;
        // dhcp
        struct dhcp *dphdr = (struct dhcp *)(packet + sizeof(ETH_HEAD) + ip_head_len + udp_head_len);

        // dhcp packet 0x800 : ipv4, 17 : udp, 68 : dhcp client
        if (ntohs(eth->type) != 0x800 || iphdr->ip_p != 17 || ntohs(udp->uh_sport) != 68)
            continue;

        // option
        // Magic Cookie (dp_optinons[0] ~[3]) = { 0x63, 0x82, 0x53, 0x63 }
        // dhcp discover
        if (dphdr->dp_options[4] != 53 || dphdr->dp_options[6] != DHCPDISCOVER)
        {
            continue;            
        }

        printPacket(eth, iphdr, udp);
        // printf("%d\n", sizeof(ETH_HEAD) + ip_total_len);
        getchar();
        write(clnt_sock, packet, sizeof(ETH_HEAD) + ip_total_len);       

    }
    pcap_close(pcap);
}