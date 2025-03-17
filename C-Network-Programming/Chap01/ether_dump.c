#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define ETH_HEADER_SIZE 14
#define INTERFACE "eth0"
#define BUFFER_SIZE 65536

struct packet_info {
    int sockfd;
    unsigned char *buffer;
    int bytes_received;
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    unsigned char *payload;
    int payload_len;
};

// Utility function to print MAC address
void print_mac(const char *label, unsigned char *mac) {
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", label,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Print payload with offset
void print_payload_with_offset(unsigned char *payload, int len) {
    printf("Payload (Hex and ASCII) with Offset:\n");
    int i, j;
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%08x  ", i);
        printf("%02x ", payload[i]);
        
        if ((i + 1) % 16 == 0) {
            printf(" | ");
            for (j = i - 15; j <= i; j++)
                printf("%c", (payload[j] >= 32 && payload[j] <= 126) ? payload[j] : '.');
            printf("\n");
        }
    }

    // Handle remaining bytes
    if (len % 16 != 0) {
        int remaining = 16 - (len % 16);
        for (i = 0; i < remaining; i++) printf("00 ");
        printf(" | ");
        for (j = len - (len % 16); j < len; j++)
            printf("%c", (payload[j] >= 32 && payload[j] <= 126) ? payload[j] : '.');
        for (i = 0; i < remaining; i++) printf(".");
        printf("\n");
    }

    // // Print additional empty lines
    // int next_offset = ((len + 15) / 16) * 16;
    // for (i = next_offset; i < next_offset + 6 * 16; i += 16) {
    //     printf("%08x  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | ................\n", i);
    // }
}

// Print IP header information
void print_ip_header(struct iphdr *ip_header) {
    printf("IP Header:\n");
    printf("  Version: %d\n", ip_header->version);
    printf("  Header Length: %d\n", ip_header->ihl * 4);
    printf("  Total Length: %d\n", ntohs(ip_header->tot_len));
    printf("  Identification: %d\n", ntohs(ip_header->id));
    printf("  Fragment Offset: %d\n", ntohs(ip_header->frag_off));
    printf("  Time to Live: %d\n", ip_header->ttl);
    printf("  Protocol: %d\n", ip_header->protocol);
    printf("  Header Checksum: 0x%04x\n", ntohs(ip_header->check));
    printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
}

// Print ICMP header information
void print_icmp_header(struct icmphdr *icmp_header) {
    printf("ICMP Header:\n");
    printf("  Type: %d\n", icmp_header->type);
    printf("  Code: %d\n", icmp_header->code);
    printf("  Checksum: 0x%04x\n", ntohs(icmp_header->checksum));
}

// Initialize raw socket
int init_socket(struct sockaddr_ll *saddr) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    saddr->sll_family = AF_PACKET;
    saddr->sll_protocol = htons(ETH_P_ALL);
    saddr->sll_ifindex = ifr.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)saddr, sizeof(*saddr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

// Process received packet
void process_packet(struct packet_info *pi, int should_print_ip_header) {
    pi->eth_header = (struct ethhdr *)pi->buffer;
    pi->payload = pi->buffer + ETH_HEADER_SIZE;
    pi->payload_len = pi->bytes_received - ETH_HEADER_SIZE;

    printf("Received %d bytes\n", pi->bytes_received);
    print_mac("Source MAC", pi->eth_header->h_source);
    print_mac("Destination MAC", pi->eth_header->h_dest);
    printf("EtherType: 0x%04x\n", ntohs(pi->eth_header->h_proto));

    if (should_print_ip_header && ntohs(pi->eth_header->h_proto) == ETH_P_IP) {
        pi->ip_header = (struct iphdr *)pi->payload;
        print_ip_header(pi->ip_header);
        
        if (pi->ip_header->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp_header = (struct icmphdr *)(pi->buffer + ETH_HEADER_SIZE + pi->ip_header->ihl * 4);
            print_icmp_header(icmp_header);
        }
    }

    print_payload_with_offset(pi->payload, pi->payload_len);
    printf("\n");
}

int main(int argc, char *argv[]) {
    int print_ip_header = (argc > 1 && strcmp(argv[1], "-i") == 0);
    struct sockaddr_ll saddr = {0};
    unsigned char buffer[BUFFER_SIZE];
    struct packet_info pi = {0};

    pi.sockfd = init_socket(&saddr);
    pi.buffer = buffer;
    printf("Capturing Ethernet frames on interface %s...\n", INTERFACE);

    while (1) {
        pi.bytes_received = recvfrom(pi.sockfd, pi.buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (pi.bytes_received < 0) {
            perror("recvfrom");
            close(pi.sockfd);
            exit(EXIT_FAILURE);
        }
        process_packet(&pi, print_ip_header);
    }

    close(pi.sockfd);
    return 0;
}