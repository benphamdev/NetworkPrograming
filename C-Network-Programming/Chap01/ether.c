// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <arpa/inet.h>
// #include <net/ethernet.h>
// #include <netinet/if_ether.h>
// #include <netpacket/packet.h>
// #include <sys/socket.h>
// #include <sys/ioctl.h>
// #include <net/if.h>

// #define BUFFER_SIZE 65536

// int main() {
//     int sockfd;
//     struct sockaddr_ll saddr;
//     unsigned char buffer[BUFFER_SIZE];
//     struct ifreq ifr;
//     char *iface = "eth0"; // Change this to your network interface

//     // Create a raw socket
//     if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
//         perror("socket");
//         exit(EXIT_FAILURE);
//     }

//     // Get the index of the network interface
//     memset(&ifr, 0, sizeof(ifr));
//     strncpy(ifr.ifr_name, iface, IFNAMSIZ);
//     if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
//         perror("ioctl");
//         close(sockfd);
//         exit(EXIT_FAILURE);
//     }

//     // Bind the socket to the network interface
//     memset(&saddr, 0, sizeof(saddr));
//     saddr.sll_family = AF_PACKET;
//     saddr.sll_protocol = htons(ETH_P_ALL);
//     saddr.sll_ifindex = ifr.ifr_ifindex;
//     if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
//         perror("bind");
//         close(sockfd);
//         exit(EXIT_FAILURE);
//     }

//     printf("Capturing Ethernet frames on interface %s...\n", iface);

//     while (1) {
//         int recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
//         if (recv_len < 0) {
//             perror("recvfrom");
//             close(sockfd);
//             exit(EXIT_FAILURE);
//         }

//         // Parse the Ethernet frame
//         struct ethhdr *eth = (struct ethhdr *)buffer;

//         printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//                eth->h_source[0], eth->h_source[1], eth->h_source[2],
//                eth->h_source[3], eth->h_source[4], eth->h_source[5]);

//         printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//                eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
//                eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

//         printf("Ethernet Type: 0x%04x\n", ntohs(eth->h_proto));

//         printf("\n");
//     }

//     close(sockfd);
//     return 0;
// }


// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <arpa/inet.h>
// #include <net/ethernet.h>
// #include <netinet/if_ether.h>
// #include <netpacket/packet.h>
// #include <sys/socket.h>
// #include <sys/ioctl.h>
// #include <net/if.h>

// #define BUFFER_SIZE 65536

// int main() {
//     int sockfd;
//     struct sockaddr_ll saddr;
//     unsigned char buffer[BUFFER_SIZE];
//     struct ifreq ifr;
//     char *iface = "eth0"; // Change this to your network interface

//     // Create a raw socket
//     if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
//         perror("socket");
//         exit(EXIT_FAILURE);
//     }

//     // Get the index of the network interface
//     memset(&ifr, 0, sizeof(ifr));
//     strncpy(ifr.ifr_name, iface, IFNAMSIZ);
//     if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
//         perror("ioctl");
//         close(sockfd);
//         exit(EXIT_FAILURE);
//     }

//     // Bind the socket to the network interface
//     memset(&saddr, 0, sizeof(saddr));
//     saddr.sll_family = AF_PACKET;
//     saddr.sll_protocol = htons(ETH_P_ALL);
//     saddr.sll_ifindex = ifr.ifr_ifindex;
//     if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
//         perror("bind");
//         close(sockfd);
//         exit(EXIT_FAILURE);
//     }

//     printf("Capturing Ethernet frames on interface %s...\n", iface);

//     while (1) {
//         int recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
//         if (recv_len < 0) {
//             perror("recvfrom");
//             close(sockfd);
//             exit(EXIT_FAILURE);
//         }

//         // Parse the Ethernet frame
//         struct ethhdr *eth = (struct ethhdr *)buffer;

//         // Print Ethernet header
//         printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//                eth->h_source[0], eth->h_source[1], eth->h_source[2],
//                eth->h_source[3], eth->h_source[4], eth->h_source[5]);

//         printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//                eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
//                eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

//         printf("Ethernet Type: 0x%04x\n", ntohs(eth->h_proto));

//         // Print the payload (data)
//         if (recv_len > sizeof(struct ethhdr)) {
//             printf("Payload (Data):\n");
//             for (int i = sizeof(struct ethhdr); i < recv_len; i++) {
//                 printf("%02x ", buffer[i]);
//                 if ((i - sizeof(struct ethhdr) + 1) % 16 == 0) {
//                     printf("\n");
//                 }
//             }
//             printf("\n");
//         }

//         printf("\n");
//     }

//     close(sockfd);
//     return 0;
// }


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define BUFFER_SIZE 65536

// Hàm tính checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Hàm kiểm tra IP header
int verify_ip_header(struct iphdr *ip) {
    unsigned short received_checksum = ip->check;
    ip->check = 0; // Đặt checksum về 0 trước khi tính toán
    unsigned short calculated_checksum = checksum(ip, ip->ihl * 4);

    if (received_checksum == calculated_checksum) {
        printf("IP Header Checksum is valid.\n");
        return 1;
    } else {
        printf("IP Header Checksum is invalid. Received: 0x%04x, Calculated: 0x%04x\n", received_checksum, calculated_checksum);
        return 0;
    }
}

// Hàm kiểm tra ICMP payload
int verify_icmp_payload(struct icmphdr *icmp, int len) {
    unsigned short received_checksum = icmp->checksum;
    icmp->checksum = 0; // Đặt checksum về 0 trước khi tính toán
    unsigned short calculated_checksum = checksum(icmp, len);

    if (received_checksum == calculated_checksum) {
        printf("ICMP Payload Checksum is valid.\n");
        return 1;
    } else {
        printf("ICMP Payload Checksum is invalid. Received: 0x%04x, Calculated: 0x%04x\n", received_checksum, calculated_checksum);
        return 0;
    }
}

// Hàm in payload
void print_payload(unsigned char *payload, int len) {
    printf("Payload (Hex and ASCII):\n");
    for (int i = 0; i < len; i++) {
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
        for (int i = 0; i < 16 - (len % 16); i++) {
            printf("   ");
        }
        printf(" | ");
        for (int j = len - (len % 16); j < len; j++) {
            if (payload[j] >= 32 && payload[j] <= 126) {
                printf("%c", payload[j]);
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
}

int main() {
    int sockfd;
    struct sockaddr_ll saddr;
    unsigned char buffer[BUFFER_SIZE];
    struct ifreq ifr;
    char *iface = "eth0"; // Thay đổi thành tên interface của bạn

    // Tạo raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Lấy index của interface mạng
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Bind socket với interface mạng
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Capturing Ethernet frames on interface %s...\n", iface);

    while (1) {
        int recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (recv_len < 0) {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Phân tích Ethernet header
        struct ethhdr *eth = (struct ethhdr *)buffer;

        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);

        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

        printf("Ethernet Type: 0x%04x\n", ntohs(eth->h_proto));

        // Phân tích IP header (nếu Ethernet Type là IPv4)
        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            printf("IP Header:\n");
            printf("  Version: %d\n", ip->version);
            printf("  IHL: %d\n", ip->ihl);
            printf("  Total Length: %d\n", ntohs(ip->tot_len));
            printf("  Protocol: %d\n", ip->protocol);
            printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
            printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));

            // Kiểm tra IP header checksum
            if (!verify_ip_header(ip)) {
                continue; // Bỏ qua gói tin nếu IP header không hợp lệ
            }

            // Phân tích ICMP payload (nếu IP protocol là ICMP)
            if (ip->protocol == IPPROTO_ICMP) {
                struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
                printf("ICMP Payload:\n");
                printf("  Type: %d\n", icmp->type);
                printf("  Code: %d\n", icmp->code);
                printf("  Checksum: 0x%04x\n", ntohs(icmp->checksum));

                // Kiểm tra ICMP payload checksum
                int icmp_len = ntohs(ip->tot_len) - ip->ihl * 4; // Độ dài ICMP payload
                if (!verify_icmp_payload(icmp, icmp_len)) {
                    continue; // Bỏ qua gói tin nếu ICMP payload không hợp lệ
                }
            }

            // In payload
            unsigned char *payload = buffer + sizeof(struct ethhdr) + ip->ihl * 4;
            int payload_len = recv_len - (sizeof(struct ethhdr) + ip->ihl * 4);
            print_payload(payload, payload_len);
        }

        printf("\n");
    }

    close(sockfd);
    return 0;
}

