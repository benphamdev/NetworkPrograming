#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main() {
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n;

    // 1. Socket type/Create tcp socket: connection-oriented stream socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    // Initialize socket structure
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 8081;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    // Bind the socket
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR on binding");

    // 2. Connection Management/Listen for connections: required for tcp only
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    printf("TCP server listening on port %d\n", portno);

    while (1) {
        //3. Client Handling/Accept connection, a new dedicated socket is created for each client
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) 
            error("ERROR on accept");

        // 4. Client identification/Handle client in a separate loop
        while (1) {
            // Read from client
            bzero(buffer, 256);
            n = read(newsockfd, buffer, 255);
            if (n < 0) error("ERROR reading from socket");
            if (n == 0) break; // Client closed connection
            printf("Message from client: %s\n", buffer);

            // Write response
            n = write(newsockfd, "Message received", 16);
            if (n < 0) error("ERROR writing to socket");
        }

        // Close connection with the current client
        close(newsockfd);
    }

    // Close the listening socket
    close(sockfd);
    return 0; 
}