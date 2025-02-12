#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8081
#define BUFFER_SIZE 1024
#define SERVER_IP "172.20.0.104"

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr;
    char buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error("Socket creation failed");
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &servaddr.sin_addr) <= 0) {
        error("Invalid address");
    }

    printf("UDP Client started. Connected to server at %s:%d\n", SERVER_IP, PORT);

    while (1) {
        // Get input from user
        printf("\nEnter message (or 'quit' to exit): ");
        if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
            error("Error reading input");
        }
        buffer[strcspn(buffer, "\n")] = 0;

        if (strcmp(buffer, "quit") == 0) {
            printf("Closing connection...\n");
            break;
        }

        // Send message to server
        if (sendto(sockfd, buffer, strlen(buffer), 0,
                  (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
            error("Error sending message");
        }
        printf("Message sent: %s\n", buffer);

        // Receive server response
        socklen_t len = sizeof(servaddr);
        int n = recvfrom(sockfd, recv_buffer, BUFFER_SIZE, 0, 
                        (struct sockaddr *)&servaddr, &len);
        if (n < 0) {
            error("Error receiving response");
        }
        recv_buffer[n] = '\0';
        printf("Server response: %s\n", recv_buffer);
    }

    close(sockfd);
    return 0;
}
