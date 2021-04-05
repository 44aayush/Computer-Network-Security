#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<stdbool.h>

#include<pcap.h>
#include<ctype.h>
#include<netinet/in.h>
#include<arpa/inet.h>

//default snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518
//Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN 6
#define ETHER_IPV4 0x800

void got_packet(u_char *args, const struct pcap_pkthdr *hander, const u_char *packet);

int main()
{
    pcap_t *handle;                           // packet capture handle
    char errbuf[ETHER_ADDR_LEN];             // error buffer
    struct bpf_program     fp;               // compiled filter program (expression)
    char filter_exp[] = "ip proto \\icmp";   // filter expression
    bpf_u_int32 net;                         // IP

    // 1. Open live pcap session on NIC with interface name
    handle = pcap_open_live("ens33", SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open device : %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // 2. Compile filter_exp into BPF pseudo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == PCAP_ERROR) {
        printf("Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
        printf("Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // 3. Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);     // Close the handle

    return 0;
}

// Ethernet header
typedef struct sniff_ethernet {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];   // destination host address
    uint8_t  ether_shost[ETHER_ADDR_LEN];   // source host address
    uint16_t ether_type;                    // protocol type (IP, ARP, RARP, etc)
} sniff_ethernet;

// IP header
typedef struct sniff_ip {
    uint8_t     ip_vhl:4,               // IP header length
                ip_ver:4;               // IP version
    uint8_t     ip_tos;                 // type of service
    uint16_t    ip_len;                 // total length
    uint16_t    ip_id;                  // identification
    uint16_t    ip_flag:3,              // fragmentation flags
                ip_offset:13;           // flags offset
    #define IP_RF 0x8000                // reserved fragment flag
    #define IP_DF 0x4000                // don't fragment flag
    #define IP_MF 0x2000                // more fragments flag
    #define IP_OFFMASK 0x1fff           // mask for fragmenting bits
    uint8_t     ip_ttl;                 // time to live
    uint8_t     ip_protocol;            // protocol type
    uint16_t    ip_chksum;              // checksum
    struct  in_addr ip_src,ip_dst;      // source and dest address
} sniff_ip;

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

// TCP header
typedef struct sniff_tcp {
    uint16_t tcp_srcport;            // source port
    uint16_t tcp_dstport;            // destination port
    uint32_t tcp_seq;                // sequence number
    uint32_t tcp_ack;                // acknowledgment number
    uint8_t  tcp_offx2;              // data offset, rsvd
    #define TCP_OFF(tcp)  (((tcp)->tcp_offx2 & 0xf0) >> 4)
    uint8_t  tcp_flags;
    #define TCP_FIN 0x01
    #define TCP_SYN 0x02
    #define TCP_RST 0x04
    #define TCP_PUSH 0x08
    #define TCP_ACK 0x10
    #define TCP_URG 0x20
    #define TCP_ECE 0x40
    #define TCP_CWR 0x80
    #define TCP_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t    tcp_win;                // window
    uint16_t    tcp_chksum;             // checksum
    uint16_t    tcp_urp;                // urgent pointer
} sniff_tcp;

void got_packet(u_char *args, const struct pcap_pkthdr *hander, const u_char *packet)
{
    static uint32_t count = 1;          // packet counter
    uint16_t sizeTcp;
    uint16_t sizeIp;
    uint16_t sizePayload;

    // Declare pointers to packet headers
    sniff_ethernet  *eth;               // The Ethernet header
    sniff_ip        *ip;                // The IP header
    sniff_tcp       *tcp;               // The TCP header
    uint8_t         *payload;           // Packet payload

    printf("Got a packet (%d):\n", count);
    count++;

    // Define Ethernet header
    eth = (sniff_ethernet *) packet;

    if (ntohs(eth->ether_type) == ETHER_IPV4) {
        ip = (sniff_ip *)(packet + sizeof(sniff_ethernet));
        sizeIp = IP_HL(ip) * 4;
        if (sizeIp < 20) {
            printf("   * Invalid IP header length: %u bytes\n", sizeIp);
            return;
        }
        printf("\nFrom: %s\n", inet_ntoa(ip->ip_src));
        printf("\nTo: %s\n", inet_ntoa(ip->ip_dst));
    }
}