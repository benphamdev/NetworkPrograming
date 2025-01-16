#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

void error(const char *msg) {
    perror(msg);
    exit(1);
}

typedef struct {
    int sockfd;
    struct sockaddr_in client_addr;
} client_info_t;

void *handle_client(void *client_info_ptr) {
    client_info_t *client_info = (client_info_t *)client_info_ptr;
    int newsockfd = client_info->sockfd;
    struct sockaddr_in client_addr = client_info->client_addr;
    char buffer[256];
    int n;

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    printf("---------------------------------------------------\n");
    printf("Connected to client %s:%d\n", client_ip, client_port);

    while (1) {
        // Read from client
        bzero(buffer, 256);
        n = read(newsockfd, buffer, 255);
        if (n < 0) error("ERROR reading from socket");
        if (n == 0) break; // Client closed connection
        printf("---------------------------------------------------\n");
        printf("Message from client %s:%d: %s\n", client_ip, client_port, buffer);

        // Write response
        n = write(newsockfd, "Message received", 16);
        if (n < 0) error("ERROR writing to socket");
    }

    // Close connection with the current client
    printf("Connection closed with client %s:%d\n", client_ip, client_port);
    close(newsockfd);
    free(client_info_ptr);
    return NULL;
}

int main() {
    int sockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    // Create socket
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

    // Listen for connections
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    printf("TCP server listening on port %d\n", portno);

    while (1) {
        // Accept connection
        client_info_t *client_info_ptr = malloc(sizeof(client_info_t));
        client_info_ptr->sockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (client_info_ptr->sockfd < 0) 
            error("ERROR on accept");
        client_info_ptr->client_addr = cli_addr;

        // Create a new thread to handle the client
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, client_info_ptr) != 0) {
            error("ERROR creating thread");
        }

        // Detach the thread so that resources are released when it finishes
        pthread_detach(thread_id);
    }

    // Close the listening socket
    close(sockfd);
    return 0; 
}