#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>

#define THREAD_POOL_SIZE 5
#define QUEUE_SIZE 10
#define PORT 8081


void error(const char *msg) {
    perror(msg);
    exit(1);
}

typedef struct {
    int sockfd;
    struct sockaddr_in client_addr;
} client_info_t;

typedef struct {
    client_info_t *queue[QUEUE_SIZE];
    int front;
    int rear;
    int count;
    pthread_mutex_t mutex;
    sem_t sem_filled;
    sem_t sem_empty;
} client_queue_t;

client_queue_t client_queue;

/**
    Initialize the client queue
    Method to initialize the client queue.
    This method initializes the front and rear pointers to 0, the count to 0, and initializes the mutex and semaphores.
 */
void queue_init(client_queue_t *q) {
    q->front = 0;
    q->rear = 0;
    q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    sem_init(&q->sem_filled, 0, 0);
    sem_init(&q->sem_empty, 0, QUEUE_SIZE);
}

/**
    Push client info to the queue
    Method to push client info to the queue.
    This method pushes the client info to the queue and updates the rear pointer.
    It also increments the count and signals the sem_filled semaphore.
 */
void queue_push(client_queue_t *q, client_info_t *client_info) {
    sem_wait(&q->sem_empty);
    pthread_mutex_lock(&q->mutex);
    q->queue[q->rear] = client_info;
    q->rear = (q->rear + 1) % QUEUE_SIZE;
    q->count++;
    pthread_mutex_unlock(&q->mutex);
    sem_post(&q->sem_filled);
}

/**
    Pop client info from the queue
    Method to pop client info from the queue.
    This method pops the client info from the queue and updates the front pointer.
    It also decrements the count and signals the sem_empty semaphore.
 */
client_info_t *queue_pop(client_queue_t *q) {
    sem_wait(&q->sem_filled);
    pthread_mutex_lock(&q->mutex);
    client_info_t *client_info = q->queue[q->front];
    q->front = (q->front + 1) % QUEUE_SIZE;
    q->count--;
    pthread_mutex_unlock(&q->mutex);
    sem_post(&q->sem_empty);
    return client_info;
}

/**
    Handle client
    Method to handle the client.
    This method reads the message from the client, writes a response, and closes the connection.
 */
void *handle_client(void *arg) {
    while (1) {
        client_info_t *client_info = queue_pop(&client_queue);
        int newsockfd = client_info->sockfd;
        struct sockaddr_in client_addr = client_info->client_addr;
        char buffer[256];
        int n;

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);

        printf("Connected to client %s:%d\n", client_ip, client_port);

        while (1) {
            // Read from client
            bzero(buffer, 256);
            n = read(newsockfd, buffer, 255);
            if (n < 0) error("ERROR reading from socket");
            if (n == 0) break; // Client closed connection
            printf("Message from client %s:%d: %s\n", client_ip, client_port, buffer);

            // Write response
            n = write(newsockfd, "Message received", 16);
            if (n < 0) error("ERROR writing to socket");
        }

        // Close connection with the current client
        printf("Connection closed with client %s:%d\n", client_ip, client_port);
        close(newsockfd);
        free(client_info);
    }
    return NULL;
}

/**
    Initialize server
    Method to initialize the server.
    This method creates a socket, initializes the socket structure, binds the socket, and listens for connections.
 */
void initialize_server(int *sockfd, struct sockaddr_in *serv_addr) {
    // Create socket
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd < 0) 
        error("ERROR opening socket");

    // Initialize socket structure
    bzero((char *) serv_addr, sizeof(*serv_addr));
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_addr.s_addr = INADDR_ANY;
    serv_addr->sin_port = htons(PORT);

    // Bind the socket
    if (bind(*sockfd, (struct sockaddr *) serv_addr, sizeof(*serv_addr)) < 0) 
        error("ERROR on binding");

    // Listen for connections
    listen(*sockfd, 5);
    printf("TCP server listening on port %d\n", PORT);
}

/**
    Create thread pool
    Method to create a thread pool.
    This method creates a thread pool of the specified size and initializes the threads.
    Create a fixed pool of threads to handle client requests.
    Reuses threads to handle multiple clients.
    Avoids the overhead of creating and destroying threads for each client request.
 */
void create_thread_pool(pthread_t *thread_pool) {
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&thread_pool[i], NULL, handle_client, NULL) != 0) {
            error("ERROR creating thread");
        }
    }
}

/**
    Accept connections
    Method to accept connections.
    This method accepts connections from clients and pushes the client info to the queue.
    Producer: Main thread accepting connections
 */
void accept_connections(int sockfd) {
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);

    while (1) {
        // Accept connection
        client_info_t *client_info_ptr = malloc(sizeof(client_info_t));
        client_info_ptr->sockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (client_info_ptr->sockfd < 0) 
            error("ERROR on accept");
        client_info_ptr->client_addr = cli_addr;

        // Push client info to queue
        queue_push(&client_queue, client_info_ptr);
    }
}

int main() {
    int sockfd;
    struct sockaddr_in serv_addr;

    // Initialize client queue
    queue_init(&client_queue);

    // Initialize server
    initialize_server(&sockfd, &serv_addr);

    // Create thread pool
    pthread_t thread_pool[THREAD_POOL_SIZE];
    create_thread_pool(thread_pool);

    // Accept connections
    accept_connections(sockfd);

    // Close the listening socket
    close(sockfd);

    return 0;
}