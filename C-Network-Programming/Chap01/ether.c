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
#define INTERFACE "eth0" // Change this to your network interface

// Function to print payload with offset
void print_payload_with_offset(unsigned char *payload, int len) {
    printf("Payload (Hex and ASCII) with Offset:\n");
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("%08x  ", i); // Print offset with 8 digits
        }
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0) {
            printf(" | ");
            for (int j = i - 15; j <= i; j++) {
                if (payload[j] >= 32 && payload[j] <= 126) {
                    printf("%c", payload[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
    if (len % 16 != 0) {
        int remaining = 16 - (len % 16);
        for (int i = 0; i < remaining; i++) {
            printf("00 ");
        }
        printf(" | ");
        for (int j = len - (len % 16); j < len; j++) {
            if (payload[j] >= 32 && payload[j] <= 126) {
                printf("%c", payload[j]);
            } else {
                printf(".");
            }
        }
        for (int i = 0; i < remaining; i++) {
            printf(".");
        }
        printf("\n");
    }
    // Print additional lines of 00 and dots to fill up to the next 6 lines
    int next_offset = ((len + 15) / 16) * 16;
    for (int i = next_offset; i < next_offset + 6 * 16; i += 16) {
        printf("%08x  ", i);
        for (int j = 0; j < 16; j++) {
            printf("00 ");
        }
        printf(" | ");
        for (int j = 0; j < 16; j++) {
            printf(".");
        }
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    int print_ip_header = 0;

    // Check for -i argument
    if (argc > 1 && strcmp(argv[1], "-i") == 0) {
        print_ip_header = 1;
    }

    int sockfd;
    struct sockaddr_ll saddr;
    unsigned char buffer[65536];
    struct ifreq ifr;

    // Create raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Get interface index
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Bind socket to network interface
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Capturing Ethernet frames on interface %s...\n", INTERFACE);

    while (1) {
        int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes_received < 0) {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        printf("Received %d bytes\n", bytes_received);

        // Print Ethernet header
        struct ethhdr *eth_header = (struct ethhdr *)buffer;
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2],
               eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2],
               eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
        printf("EtherType: 0x%04x\n", ntohs(eth_header->h_proto));

        // Check for IP packets
        if (print_ip_header && ntohs(eth_header->h_proto) == ETH_P_IP) {
            struct iphdr *ip_header = (struct iphdr *)(buffer + ETH_HEADER_SIZE);
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

            // Check for ICMP packets
            if (ip_header->protocol == IPPROTO_ICMP) {
                struct icmphdr *icmp_header = (struct icmphdr *)(buffer + ETH_HEADER_SIZE + ip_header->ihl * 4);
                printf("ICMP Header:\n");
                printf("  Type: %d\n", icmp_header->type);
                printf("  Code: %d\n", icmp_header->code);
                printf("  Checksum: 0x%04x\n", ntohs(icmp_header->checksum));
            }
        }

        // Print payload with offset
        unsigned char *recv_payload = buffer + ETH_HEADER_SIZE;
        int recv_payload_len = bytes_received - ETH_HEADER_SIZE;
        print_payload_with_offset(recv_payload, recv_payload_len);

        printf("\n");
    }

    // Clean up
    close(sockfd);
    return 0;
}