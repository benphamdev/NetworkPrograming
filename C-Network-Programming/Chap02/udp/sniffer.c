#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>

#define BUFFER_SIZE 65536
#define INTERFACE "eth0"
#define LOCAL_SERVER_HOST "127.0.0.1"
#define LOCAL_SERVER_PORT 9090

void send_to_local_server(const char *msg) {
    int sockfd;
    struct sockaddr_in servaddr;
    char recv_buffer[1024];

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        return;
    }

    // Configure server address
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(LOCAL_SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_HOST);

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 1;  // 1 second timeout
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Send message
    printf("\nSending to server: %s\n", msg);
    if (sendto(sockfd, msg, strlen(msg), 0, 
        (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        printf("Failed to send: %s\n", strerror(errno));
        close(sockfd);
        return;
    }

    // Wait for acknowledgment
    socklen_t len = sizeof(servaddr);
    int n = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer)-1, 0,
                     (struct sockaddr *)&servaddr, &len);
    
    if (n > 0) {
        recv_buffer[n] = '\0';
        printf("Received ACK: %s\n", recv_buffer);
    } else {
        printf("No acknowledgment received\n");
    }

    close(sockfd);
}

void process_packet(unsigned char *buffer, int size) {
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    int ip_header_len = ip_header->ihl * 4;

    if (ip_header->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_header = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + ip_header_len);
        struct sockaddr_in source;
        source.sin_addr.s_addr = ip_header->saddr;

        char message[1024];
        snprintf(message, sizeof(message), "Intercepted ICMP from %s, type: %d", 
                inet_ntoa(source.sin_addr), icmp_header->type);
        
        printf("[Packet] %s\n", message);
        send_to_local_server(message);
    }
    else if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip_header_len);
        struct sockaddr_in source;
        source.sin_addr.s_addr = ip_header->saddr;

        char message[1024];
        snprintf(message, sizeof(message), "Intercepted TCP from %s, port: %d", 
                inet_ntoa(source.sin_addr), ntohs(tcp_header->th_sport));  // Fixed member name
        
        printf("[Packet] %s\n", message);
        send_to_local_server(message);
    }
}

int main() {
    int sockfd;
    struct ifreq ifreq_i;
    struct sockaddr_ll sll;
    unsigned char *buffer = malloc(BUFFER_SIZE);
    
    printf("Starting sniffer...\n");

    // Create raw socket
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Get interface index
    strncpy(ifreq_i.ifr_name, INTERFACE, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifreq_i) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        exit(1);
    }

    // Bind to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifreq_i.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(1);
    }

    printf("Listening on interface %s...\n", INTERFACE);
    printf("Local server: %s:%d\n", LOCAL_SERVER_HOST, LOCAL_SERVER_PORT);

    while (1) {
        int packet_size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (packet_size < 0) {
            printf("Packet receive error: %s\n", strerror(errno));
            continue;
        }
        process_packet(buffer, packet_size);
    }

    close(sockfd);
    free(buffer);
    return 0;
}