#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>  // Add this for errno

#define PORT 9090
#define BUFFER_SIZE 1024
#define CLIENT_PORT 8081  // Define the client port to forward messages
#define FAKE_INDEX_HTML "<!DOCTYPE html>\n" \
    "<html>\n" \
    "<head><title>Fake Google</title></head>\n" \
    "<body>\n" \
    "<h1>This is a fake Google page</h1>\n" \
    "<p>You have been intercepted!</p>\n" \
    "</body>\n" \
    "</html>\n"

void error(const char *msg) {
    perror(msg);
    exit(1);
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
        
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE-1, 0, (struct sockaddr *)&clientaddr, &len);
        if (n < 0) {
            printf("Error receiving data: %s (errno: %d)\n", strerror(errno), errno);
            continue;
        }
        
        buffer[n] = '\0';
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        printf("\n[%s] Received message from %s:%d\n", 
               timestamp, inet_ntoa(clientaddr.sin_addr), 
               ntohs(clientaddr.sin_port));
        printf("Message content (%d bytes): %s\n", n, buffer);
        fflush(stdout);

        // Send immediate acknowledgment
        const char *ack = "ACK: Message received by local_server";
        if (sendto(sockfd, ack, strlen(ack), 0, (struct sockaddr *)&clientaddr, len) < 0) {
            printf("Error sending ACK: %s\n", strerror(errno));
        } else {
            printf("Sent ACK to %s:%d\n", 
                   inet_ntoa(clientaddr.sin_addr), 
                   ntohs(clientaddr.sin_port));
        }
        fflush(stdout);

        // Log based on message type (Ping, HTTP, etc.)
        if (strstr(buffer, "Ping intercepted from") != NULL) {
            char victim_ip[INET_ADDRSTRLEN] = {0};
            char forwarded_by[INET_ADDRSTRLEN] = {0};
            if (sscanf(buffer, "Ping intercepted from %15s, forwarded by %15s", victim_ip, forwarded_by) == 2) {
                printf("Parsed sniffer info - Victim IP: %s, Forwarder IP: %s\n", victim_ip, forwarded_by);
            }
        }

        if (strstr(buffer, "HTTP request intercepted from") != NULL) {
            // Send fake index.html page as response
            const char *response = FAKE_INDEX_HTML;
            if (sendto(sockfd, response, strlen(response), 0, (struct sockaddr *)&clientaddr, len) < 0) {
                error("Error sending fake page");
            }
            printf("Fake page sent to client at %s\n", inet_ntoa(clientaddr.sin_addr));
        } else {
            // Forward the message to the client
            memset(&forwardaddr, 0, sizeof(forwardaddr));
            forwardaddr.sin_family = AF_INET;
            forwardaddr.sin_port = htons(CLIENT_PORT);
            forwardaddr.sin_addr = clientaddr.sin_addr;  // Forward to the same IP

            if (sendto(sockfd, buffer, n, 0, (struct sockaddr *)&forwardaddr, sizeof(forwardaddr)) < 0) {
                perror("Error forwarding message");
            } else {
                printf("Message forwarded to client at %s:%d\n", inet_ntoa(forwardaddr.sin_addr), CLIENT_PORT);
            }

            const char *ack_msg = "Message received and processed by local server";
            if (sendto(sockfd, ack_msg, strlen(ack_msg), 0, (struct sockaddr *)&clientaddr, len) < 0) {
                perror("Error sending acknowledgment");
            } else {
                printf("Acknowledgment sent to sniffer\n");
            }
        }
    }
    close(sockfd);
    return 0;
}