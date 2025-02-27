#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#define LOCAL_PORT 9000          // Port on local host machine
#define REMOTE_PORT 80         // Port on virtual machine
#define BUFFER_SIZE 16384
#define MAX_SESSIONS 10          // Maximum number of concurrent connections

typedef struct {
    ssh_session ssh;
    ssh_channel channel;
    int client_sock;
    int running;
} forward_tunnel_t;

// Global variables for cleanup
int server_sock = -1;
int keep_running = 1;
forward_tunnel_t sessions[MAX_SESSIONS];
pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;

// Signal handler for clean termination
void signal_handler(int signo) {
    printf("\nReceived signal %d. Shutting down...\n", signo);
    keep_running = 0;
    
    // Close server socket to break accept() loop
    if (server_sock != -1) {
        close(server_sock);
        server_sock = -1;
    }
}

// Error reporting helper
void error_exit(const char* message, ssh_session session) {
    fprintf(stderr, "Error: %s\n", message);
    if (session) {
        fprintf(stderr, "SSH error: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
    }
    exit(EXIT_FAILURE);
}

// Function to create server socket for accepting local connections
int create_server_socket(int port) {
    int sock;
    struct sockaddr_in addr;
    int opt = 1;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    // Set socket options
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sock);
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    
    if (listen(sock, 5) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }
    
    // Set to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    return sock;
}

// Create and authenticate SSH session
ssh_session create_ssh_session(const char* host, const char* username, const char* password) {
    ssh_session session = ssh_new();
    if (session == NULL) {
        error_exit("Failed to create SSH session", NULL);
    }
    
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    
    int verbosity = SSH_LOG_NOLOG;
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    
    if (ssh_connect(session) != SSH_OK) {
        error_exit("Failed to connect", session);
    }
    
    printf("Connected to %s\n", host);
    
    if (ssh_userauth_password(session, NULL, password) != SSH_AUTH_SUCCESS) {
        error_exit("Authentication failed", session);
    }
    
    printf("Authentication successful\n");
    return session;
}

// Thread function to handle tunneling for a connection
void* connection_handler(void* arg) {
    forward_tunnel_t* tunnel = (forward_tunnel_t*)arg;
    ssh_channel channel = tunnel->channel;
    int client_sock = tunnel->client_sock;
    char buffer[BUFFER_SIZE];
    int nbytes, nwritten;
    fd_set fds;
    struct timeval tv;
    
    // Mark session as running
    tunnel->running = 1;
    
    printf("Starting port forwarding: local:%d -> remote:%d\n", LOCAL_PORT, REMOTE_PORT);
    
    while (tunnel->running && keep_running) {
        FD_ZERO(&fds);
        FD_SET(client_sock, &fds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout
        
        // Check for data from local client
        if (select(client_sock + 1, &fds, NULL, NULL, &tv) > 0) {
            if (FD_ISSET(client_sock, &fds)) {
                nbytes = read(client_sock, buffer, BUFFER_SIZE);
                if (nbytes <= 0) {
                    // Client closed connection or error
                    break;
                }
                
                // Forward data to remote server via SSH channel
                nwritten = ssh_channel_write(channel, buffer, nbytes);
                if (nwritten <= 0) {
                    fprintf(stderr, "Error writing to channel\n");
                    break;
                }
            }
        }
        
        // Check for data from remote server
        nbytes = ssh_channel_read_nonblocking(channel, buffer, BUFFER_SIZE, 0);
        if (nbytes > 0) {
            // Forward data back to local client
            nwritten = write(client_sock, buffer, nbytes);
            if (nwritten <= 0) {
                fprintf(stderr, "Error writing to socket\n");
                break;
            }
        } else if (nbytes < 0) {
            // Error or channel closed
            break;
        }
        
        // Check if channel is closed
        if (ssh_channel_is_closed(channel)) {
            break;
        }
    }
    
    printf("Closing connection\n");
    
    // Clean up this connection
    pthread_mutex_lock(&session_mutex);
    tunnel->running = 0;
    if (channel) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        tunnel->channel = NULL;
    }
    if (client_sock != -1) {
        close(client_sock);
        tunnel->client_sock = -1;
    }
    pthread_mutex_unlock(&session_mutex);
    
    return NULL;
}

int find_free_session() {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].running) {
            return i;
        }
    }
    return -1;
}

int main(int argc, char *argv[]) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    ssh_session master_session;
    pthread_t thread_id;
    
    // Check arguments
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <remote_host> <username> <password>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.255.150 chienpham password123\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize sessions
    for (int i = 0; i < MAX_SESSIONS; i++) {
        sessions[i].running = 0;
        sessions[i].client_sock = -1;
        sessions[i].channel = NULL;
    }
    
    // Create master SSH session
    master_session = create_ssh_session(argv[1], argv[2], argv[3]);
    
    // Create server socket for local connections
    server_sock = create_server_socket(LOCAL_PORT);
    if (server_sock < 0) {
        ssh_disconnect(master_session);
        ssh_free(master_session);
        exit(EXIT_FAILURE);
    }
    
    printf("Listening on port %d, forwarding to %s:%d\n", 
           LOCAL_PORT, argv[1], REMOTE_PORT);
    printf("Press Ctrl+C to quit\n");
    
    // Main loop to accept connections
    while (keep_running) {
        // Accept client connections (non-blocking)
        int client_sock = accept(server_sock, (struct sockaddr*)&addr, &addrlen);
        if (client_sock < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No connections pending, wait a bit
                usleep(100000); // 100ms
                continue;
            }
            
            if (errno != EINTR) { // Not interrupted by signal
                perror("accept");
            }
            break;
        }
        
        printf("New connection from %s:%d\n", 
               inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        
        // Find a free session slot
        pthread_mutex_lock(&session_mutex);
        int slot = find_free_session();
        if (slot < 0) {
            fprintf(stderr, "Maximum sessions reached, rejecting connection\n");
            close(client_sock);
            pthread_mutex_unlock(&session_mutex);
            continue;
        }
        
        // Create a new SSH channel for direct TCP/IP forwarding
        ssh_channel channel = ssh_channel_new(master_session);
        if (channel == NULL) {
            fprintf(stderr, "Failed to create channel\n");
            close(client_sock);
            pthread_mutex_unlock(&session_mutex);
            continue;
        }
        
        // Open direct forwarding channel
        if (ssh_channel_open_forward(channel, "127.0.0.1", REMOTE_PORT, "127.0.0.1", 0) != SSH_OK) {
            fprintf(stderr, "Failed to open forward: %s\n", ssh_get_error(master_session));
            ssh_channel_free(channel);
            close(client_sock);
            pthread_mutex_unlock(&session_mutex);
            continue;
        }
        
        // Set up the tunnel structure
        sessions[slot].ssh = master_session;
        sessions[slot].channel = channel;
        sessions[slot].client_sock = client_sock;
        
        // Create a thread to handle this connection
        if (pthread_create(&thread_id, NULL, connection_handler, &sessions[slot]) != 0) {
            fprintf(stderr, "Failed to create thread\n");
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            close(client_sock);
            sessions[slot].running = 0;
            sessions[slot].client_sock = -1;
            sessions[slot].channel = NULL;
        } else {
            // Detach the thread so it can clean up on its own
            pthread_detach(thread_id);
        }
        
        pthread_mutex_unlock(&session_mutex);
    }
    
    printf("Shutting down...\n");
    
    // Clean up all sessions
    pthread_mutex_lock(&session_mutex);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].running) {
            sessions[i].running = 0;
            if (sessions[i].channel) {
                ssh_channel_close(sessions[i].channel);
                ssh_channel_free(sessions[i].channel);
                sessions[i].channel = NULL;
            }
            if (sessions[i].client_sock != -1) {
                close(sessions[i].client_sock);
                sessions[i].client_sock = -1;
            }
        }
    }
    pthread_mutex_unlock(&session_mutex);
    
    // Clean up server
    if (server_sock != -1) {
        close(server_sock);
    }
    
    // Clean up master SSH session
    ssh_disconnect(master_session);
    ssh_free(master_session);
    
    printf("Port forwarding stopped\n");
    
    return 0;
}
