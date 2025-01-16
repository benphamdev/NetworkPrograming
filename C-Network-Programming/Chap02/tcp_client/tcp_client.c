#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_PORT 8081 // Change this to your server's port
#define SERVER_IP "172.20.0.100" // Change this to your server's IP address

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024];
    char message[1024];
    int n;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }

    // Set server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        error("ERROR invalid server IP address");
    }

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        error("ERROR connecting to server");
    }

    while (1) {
        printf("Enter message: ");
        fflush(stdout); // Ensure the prompt is displayed immediately
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = 0; // Remove newline character

        // Send message to server
        n = write(sockfd, message, strlen(message));
        if (n < 0) {
            error("ERROR writing to socket");
        }

        // Read response from server
        memset(buffer, 0, sizeof(buffer));
        n = read(sockfd, buffer, sizeof(buffer) - 1);
        if (n < 0) {
            error("ERROR reading from socket");
        }
        buffer[n] = '\0'; // Null-terminate the received string
        printf("Response from server: %s\n", buffer);
    }

    // Close socket
    close(sockfd);
    return 0;
}