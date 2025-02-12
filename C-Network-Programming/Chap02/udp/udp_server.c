#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8081
#define BUFFER_SIZE 1024

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr, clientaddr;
    char buffer[BUFFER_SIZE];
    socklen_t len;

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error("Socket creation failed");
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&clientaddr, 0, sizeof(clientaddr));

    // Server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        error("Bind failed");
    }

    printf("UDP Server started. Listening on port %d...\n", PORT);

    while (1) {
        len = sizeof(clientaddr);
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                         (struct sockaddr *)&clientaddr, &len);
        if (n < 0) {
            error("Error receiving message");
        }
        buffer[n] = '\0';

        printf("Received message from client: %s\n", buffer);

        // Send acknowledgment message back to client
        const char *ack_msg = "Message received!";
        if (sendto(sockfd, ack_msg, strlen(ack_msg), 0,
                   (const struct sockaddr *)&clientaddr, len) < 0) {
            error("Error sending acknowledgment");
        }
        printf("Acknowledgment sent to client: %s\n", ack_msg);
    }

    close(sockfd);
    return 0;
}
