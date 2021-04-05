#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <pcap.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN        1518
// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN  6
#define ETHER_IPV4      0x800

void got_packet(u_char *args, const struct pcap_pkthdr *hander, const u_char *packet);
void print_hex_ascii_line(const uint8_t *payload, int len, int offset);
void print_payload(const uint8_t *payload, int len);

int main()
{
    pcap_t *handle;                            // packet capture handle
    char errbuf[ETHER_ADDR_LEN];             // error buffer
    struct bpf_program     fp;                 // compiled filter program (expression)
    char filter_exp[] = "proto TCP and dst portrange 10-100";   // filter expression
    bpf_u_int32 net;                                // IP

    // 1. Open live pcap session on NIC with interface name
    handle = pcap_open_live("enp0s3", SNAP_LEN, 1, 1000, errbuf);
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
    uint16_t    tcp_srcport;            // source port
    uint16_t    tcp_dstport;            // destination port
    uint32_t    tcp_seq;                // sequence number
    uint32_t    tcp_ack;                // acknowledgment number
    uint8_t     tcp_offx2;              // data offset, rsvd
    #define TCP_OFF(tcp)  (((tcp)->tcp_offx2 & 0xf0) >> 4)
    uint8_t     tcp_flags;
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
    uint16_t        sizeTcp;
    uint16_t        sizeIp;
    uint16_t        sizePayload;

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
        printf("\tFrom: %s\n", inet_ntoa(ip->ip_src));
        printf("\tTo: %s\n", inet_ntoa(ip->ip_dst));
    }

    tcp = (sniff_tcp *)(packet + sizeof(sniff_ethernet) + sizeIp);
    sizeTcp = TCP_OFF(tcp) * 4;
    if ( sizeTcp < 20){
	printf("Invalid TCP header length: %u bytes", sizeTcp);
	return;
    }

        printf("       Source Port: %d\n", ntohs(tcp->tcp_srcport));
        printf("  Destination Port: %d\n", ntohs(tcp->tcp_dstport));

        switch (ip->ip_protocol){
            case IPPROTO_ICMP:
                printf("          Protocol: ICMP\n");
                break;
            case IPPROTO_TCP:
                printf("          Protocol: TCP\n");
                break;
            case IPPROTO_UDP:
                printf("          Protocol: UDP\n");
                break;
            case IPPROTO_IP:
                printf("          Protocol: IP\n");
                break;            default:
                printf("          Protocol: Others\n");
        }


    // define/compute tcp payload (segment) offset
    payload = (uint8_t *)(packet + sizeof(sniff_ethernet) + sizeIp + sizeTcp);

    // compute tcp payload (segment) size
    sizePayload = ntohs(ip->ip_len) - (sizeIp + sizeTcp);

    // Print payload data; it might be binary, so don't just treat it as a string.
    if (sizePayload > 0) {
	printf("          Payload: %d bytes\n", sizePayload);
	print_payload(payload, sizePayload);
    }    
}

// print data in rows of 16 bytes: offset   hex   ASCII
// 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
void print_hex_ascii_line(const uint8_t *payload, int len, int offset)
{
    int     i;
    int     gap;
    const uint8_t *ch;

    // offset
    printf("    %05d   ", offset);

    // hex
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        // print extra space after 8th byte for visual aid
        if (i == 7) printf(" ");
    }
    // print space to handle line less than 8 bytes
    if (len < 8) printf(" ");

    // fill hex gap with spaces if not full line
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) printf("   ");
    }
    printf("   ");

    // ASCII (if printable)
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch)) printf("%c", *ch);
        else printf(".");
        ch++;
    }
    printf("\n");
}

// print packet payload data (avoid printing binary data)
void print_payload(const uint8_t *payload, int len)
{
    int     len_rem = len;
    int     line_width = 16;                // number of bytes per line
    int     line_len;
    int     offset = 0;                     // zero-based offset counter
    const uint8_t *ch = payload;

    if (len <= 0) return;

    // data fits on one line
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    // data spans multiple lines
    while(1) {
        // compute current line length
        line_len = line_width % len_rem;
        // print line
        print_hex_ascii_line(ch, line_len, offset);
        // compute total remaining
        len_rem = len_rem - line_len;
        // shift pointer to remaining bytes to print
        ch = ch + line_len;
        // add offset
        offset = offset + line_width;
        // check if we have line width chars or less
        if (len_rem <= line_width) {
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}