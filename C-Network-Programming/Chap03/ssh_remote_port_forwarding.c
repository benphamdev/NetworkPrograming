#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define REMOTE_PORT 8080  // Port to listen on remote server
#define BUFFER_SIZE 4096

// Global variables for cleanup
ssh_session session = NULL;
volatile sig_atomic_t keep_running = 1;

// Signal handler for clean termination
void signal_handler(int signo) {
    printf("\nReceived signal %d. Shutting down...\n", signo);
    keep_running = 0;
}

// Error reporting helper
void error_exit(const char* message) {
    fprintf(stderr, "Error: %s\n", message);
    if (session) {
        fprintf(stderr, "SSH error: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
    }
    exit(EXIT_FAILURE);
}

// Create and authenticate SSH session
ssh_session create_ssh_session(const char* host, const char* username, const char* password) {
    ssh_session ssh = ssh_new();
    if (ssh == NULL) {
        error_exit("Failed to create SSH session");
    }
    
    ssh_options_set(ssh, SSH_OPTIONS_HOST, host);
    ssh_options_set(ssh, SSH_OPTIONS_USER, username);
    
    int verbosity = SSH_LOG_PROTOCOL;
    ssh_options_set(ssh, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    
    if (ssh_connect(ssh) != SSH_OK) {
        fprintf(stderr, "Connection error: %s\n", ssh_get_error(ssh));
        ssh_free(ssh);
        return NULL;
    }
    
    printf("Connected to %s\n", host);
    
    if (ssh_userauth_password(ssh, NULL, password) != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Authentication error: %s\n", ssh_get_error(ssh));
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return NULL;
    }
    
    printf("Authentication successful\n");
    return ssh;
}

// Remote port forwarding with web server functionality
int remote_web_server(ssh_session ssh) {
    int rc;
    ssh_channel channel;
    char buffer[BUFFER_SIZE];
    int nbytes, nwritten;
    int port = 0;
    char *peer_address = NULL;
    int peer_port = 0;
    
    // HTML response to serve
    const char *html_response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "Content-Length: 340\r\n"
        "\r\n"
        "<!DOCTYPE html>\n"
        "<html>\n"
        "  <head>\n"
        "    <title>SSH Remote Port Forwarding</title>\n"
        "    <style>\n"
        "      body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }\n"
        "      h1 { color: #4285f4; }\n"
        "    </style>\n"
        "  </head>\n"
        "  <body>\n"
        "    <h1>SSH Remote Port Forwarding</h1>\n"
        "    <p>This web page is served through an SSH tunnel!</p>\n"
        "  </body>\n"
        "</html>\n";

    printf("Setting up remote port forwarding on port %d...\n", REMOTE_PORT);
    
    // Setup remote port forwarding
    rc = ssh_channel_listen_forward(ssh, NULL, REMOTE_PORT, NULL);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error opening remote port %d: %s\n", 
                REMOTE_PORT, ssh_get_error(ssh));
        return rc;
    }
    
    printf("Remote port forwarding established. Remote server now listening on port %d\n", REMOTE_PORT);
    printf("You can access the web server by connecting to port %d on the remote server\n", REMOTE_PORT);
    printf("Press Ctrl+C to stop the server\n");
    
    // Main loop to accept and handle connections
    while (keep_running) {
        printf("Waiting for incoming connection...\n");
        
        // Accept forwarded connection
        channel = ssh_channel_open_forward_port(ssh, 60000, &port, &peer_address, &peer_port);
        if (channel == NULL) {
            if (!keep_running) {
                // Clean exit requested
                break;
            }
            fprintf(stderr, "Error waiting for incoming connection: %s\n", ssh_get_error(ssh));
            sleep(1); // Wait a bit before retrying
            continue;
        }

        printf("Connection received from %s:%d\n", peer_address, peer_port);
        
        // Read the HTTP request
        bzero(buffer, sizeof(buffer));
        nbytes = ssh_channel_read_timeout(channel, buffer, sizeof(buffer) - 1, 0, 5000);
        if (nbytes <= 0) {
            fprintf(stderr, "Error reading request or timeout: %s\n", ssh_get_error(ssh));
            ssh_channel_send_eof(channel);
            ssh_channel_free(channel);
            ssh_string_free_char(peer_address);
            continue;
        }
        
        // Print the request
        buffer[nbytes] = '\0';
        printf("Received HTTP request:\n%s\n", buffer);
        
        // Only respond to GET requests
        if (strncmp(buffer, "GET ", 4) == 0) {
            printf("Processing GET request\n");
            
            // Send the HTTP response
            nbytes = strlen(html_response);
            nwritten = ssh_channel_write(channel, html_response, nbytes);
            if (nwritten != nbytes) {
                fprintf(stderr, "Error sending response: %s\n", ssh_get_error(ssh));
            } else {
                printf("Response sent successfully to %s:%d\n", peer_address, peer_port);
            }
        } else {
            printf("Received non-GET request, ignoring\n");
        }
        
        // Close the channel for this connection
        ssh_channel_send_eof(channel);
        ssh_channel_free(channel);
        ssh_string_free_char(peer_address);
    }
    
    return SSH_OK;
}

int main(int argc, char *argv[]) {
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Check command line arguments
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ssh_server> <username> <password>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.255.151 chienpham password123\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // Create SSH session
    session = create_ssh_session(argv[1], argv[2], argv[3]);
    if (session == NULL) {
        error_exit("Failed to create SSH session");
    }
    
    printf("SSH session established to %s\n", argv[1]);
    
    // Start the remote port forwarding web server
    int rc = remote_web_server(session);
    
    // Clean up
    ssh_disconnect(session);
    ssh_free(session);
    
    if (rc == SSH_OK) {
        printf("Program terminated normally\n");
        return 0;
    } else {
        fprintf(stderr, "Program terminated with error\n");
        return 1;
    }

    
}
