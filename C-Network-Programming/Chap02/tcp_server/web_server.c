#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <fcntl.h>

#define MAX_EVENTS 10
#define PORT 8081  // Keep port 8081 as requested

typedef struct {
    int fd;
    struct sockaddr_in addr;
} client_info_t;

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        error("fcntl F_GETFL");
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        error("fcntl F_SETFL");
    }
}

void handle_client(client_info_t *client) {
    char buffer[1024];
    int n;
    char client_ip[INET_ADDRSTRLEN];

    // Get client IP address
    inet_ntop(AF_INET, &(client->addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client->addr.sin_port);

    // Read HTTP request from client
    bzero(buffer, 1024);
    n = read(client->fd, buffer, 1023);
    if (n < 0) {
        perror("ERROR reading from socket");
        close(client->fd);
        return;
    }
    if (n == 0) {
        close(client->fd);
        return;
    }
    printf("[Web] Received request from %s:%d\n", client_ip, client_port);
    printf("Request from client %s:%d: %s\n", client_ip, client_port, buffer);

    // Write HTTP response
    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "Content-Length: 200\r\n"
        "\r\n"
        "<html><body><h1>Hacked!</h1>"
        "<p>This page has been intercepted by the attacker.</p>"
        "<p>Original request was for: google.com</p>"
        "</body></html>";
    n = write(client->fd, response, strlen(response));
    if (n < 0) {
        perror("ERROR writing to socket");
    }

    // Close connection with the current client
    close(client->fd);
}

int create_and_bind_socket() {
    int sockfd;
    struct sockaddr_in serv_addr;
    int opt = 1;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    // Thêm SO_REUSEADDR
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        error("ERROR on setsockopt");

    // Initialize socket structure
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR on binding");

    printf("Web server bound to all interfaces on port %d\n", PORT);
    return sockfd;
}

void setup_epoll(int epollfd, int sockfd) {
    struct epoll_event ev;

    // Add listening socket to epoll
    ev.events = EPOLLIN;
    ev.data.fd = sockfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        error("epoll_ctl: listen_sock");
    }
}

void accept_and_add_to_epoll(int epollfd, int sockfd) {
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    struct epoll_event ev;
    int newsockfd;

    // Accept new connection
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd == -1) {
        perror("accept");
        return;
    }
    set_nonblocking(newsockfd);

    client_info_t *client = malloc(sizeof(client_info_t));
    client->fd = newsockfd;
    client->addr = cli_addr;

    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = client;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, newsockfd, &ev) == -1) {
        free(client);
        error("epoll_ctl: conn_sock");
    }
}

void event_loop(int epollfd, int sockfd) {
    struct epoll_event events[MAX_EVENTS];
    int nfds;

    while (1) {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            error("epoll_wait");
        }

        for (int n = 0; n < nfds; ++n) {
            if (events[n].data.fd == sockfd) {
                accept_and_add_to_epoll(epollfd, sockfd);
            } else {
                client_info_t *client = (client_info_t *)events[n].data.ptr;
                handle_client(client);
                free(client);
            }
        }
    }
}

int main() {
    int sockfd, epollfd;

    // Create and bind socket
    sockfd = create_and_bind_socket();

    // Listen for connections
    listen(sockfd, 5);
    printf("Web server listening on port %d\n", PORT);

    // Set socket to non-blocking
    set_nonblocking(sockfd);

    // Create epoll instance
    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        error("epoll_create1");
    }

    // Setup epoll
    setup_epoll(epollfd, sockfd);

    // Start event loop
    event_loop(epollfd, sockfd);

    // Close the listening socket
    close(sockfd);

    return 0;
}


