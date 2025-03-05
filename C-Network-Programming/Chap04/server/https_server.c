#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 9443
#define BUFFER_SIZE 4096

// Global SSL context
SSL_CTX *ssl_ctx;

// HTTP response headers
const char* HTTP_200_OK = "HTTP/1.1 200 OK\r\n";
const char* HTTP_404_NOT_FOUND = "HTTP/1.1 404 Not Found\r\n";
const char* CONTENT_TYPE_HTML = "Content-Type: text/html\r\n";
const char* CONTENT_TYPE_JSON = "Content-Type: application/json\r\n";

// Sample HTML content for the home page
const char* INDEX_HTML = "<!DOCTYPE html>\n"
    "<html>\n"
    "<head><title>HTTPS Server in C</title></head>\n"
    "<body>\n"
    "<h1>Hello from HTTPS Server</h1>\n"
    "<p>This page is served over HTTPS using OpenSSL.</p>\n"
    "</body>\n"
    "</html>\n";

// Structure to pass client info to thread
typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
    SSL *ssl;  // Added SSL object
} client_info_t;

// Function to initialize SSL context
SSL_CTX* init_ssl_context() {
    SSL_CTX *ctx;

    // Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create new SSL context with TLS method
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the certificate file to use
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the private key file to use
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

    // Force TLS 1.2 - uncomment to disable TLS 1.3 for packet inspection
    // SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
    
    return ctx;
}

// Function to serve files or generate dynamic content
void serve_request(SSL *ssl, char *request) {
    char method[10], path[255];
    
    // Parse the request to get method and path
    if (sscanf(request, "%s %s", method, path) != 2) {
        return;  // Invalid request format
    }
    
    printf("Method: %s, Path: %s\n", method, path);
    
    // Handle different paths
    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        // Serve index page
        char response[BUFFER_SIZE];
        sprintf(response, "%s%s\r\nContent-Length: %lu\r\n\r\n%s", 
                HTTP_200_OK, 
                CONTENT_TYPE_HTML, 
                strlen(INDEX_HTML), 
                INDEX_HTML);
        
        SSL_write(ssl, response, strlen(response));
    } 
    else if (strcmp(path, "/api/status") == 0) {
        // Example API endpoint returning JSON
        const char* json = "{\"status\":\"running\",\"secure\":true}\n";
        
        char response[BUFFER_SIZE];
        sprintf(response, "%s%s\r\nContent-Length: %lu\r\n\r\n%s", 
                HTTP_200_OK, 
                CONTENT_TYPE_JSON, 
                strlen(json), 
                json);
        
        SSL_write(ssl, response, strlen(response));
    }
    else {
        // 404 Not Found
        const char* not_found = "<html><body><h1>404 Not Found</h1></body></html>\n";
        
        char response[BUFFER_SIZE];
        sprintf(response, "%s%s\r\nContent-Length: %lu\r\n\r\n%s", 
                HTTP_404_NOT_FOUND, 
                CONTENT_TYPE_HTML, 
                strlen(not_found), 
                not_found);
        
        SSL_write(ssl, response, strlen(response));
    }
}

// Thread function to handle client connections
void* handle_client(void* arg) {
    client_info_t* client_info = (client_info_t*)arg;
    char buffer[BUFFER_SIZE] = {0};
    int bytes_read;
    
    // Get SSL object from client info
    SSL *ssl = client_info->ssl;
    
    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    printf("SSL connection established with %s:%d\n", 
           inet_ntoa(client_info->client_addr.sin_addr),
           ntohs(client_info->client_addr.sin_port));
    
    // Read client's request
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';  // Null terminate
        printf("Received request:\n%s\n", buffer);
        
        // Process the request and send response
        serve_request(ssl, buffer);
    }
    
cleanup:
    // Clean up and close connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_info->client_socket);
    free(client_info);
    
    return NULL;
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    pthread_t thread_id;
    
    // Initialize SSL Context
    ssl_ctx = init_ssl_context();
    printf("SSL context initialized\n");
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    // Set up address structure
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind socket to address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("HTTPS Server started on port %d\n", PORT);
    printf("Access at: https://localhost:%d\n", PORT);
    printf("Test with: curl -k https://localhost:%d\n", PORT);
    
    // Main server loop
    while(1) {
        client_info_t* client_info = malloc(sizeof(client_info_t));
        if (!client_info) {
            perror("Failed to allocate memory");
            continue;
        }
        
        socklen_t addrlen = sizeof(client_info->client_addr);
        
        // Accept client connection
        client_info->client_socket = accept(server_fd, 
                                          (struct sockaddr*)&client_info->client_addr,
                                          &addrlen);
        
        if (client_info->client_socket < 0) {
            perror("accept failed");
            free(client_info);
            continue;
        }
        
        printf("Connection accepted from %s:%d\n", 
               inet_ntoa(client_info->client_addr.sin_addr),
               ntohs(client_info->client_addr.sin_port));
        
        // Create new SSL object for this connection
        client_info->ssl = SSL_new(ssl_ctx);
        if (!client_info->ssl) {
            perror("SSL_new failed");
            close(client_info->client_socket);
            free(client_info);
            continue;
        }
        
        // Set the socket for SSL
        if (!SSL_set_fd(client_info->ssl, client_info->client_socket)) {
            perror("SSL_set_fd failed");
            SSL_free(client_info->ssl);
            close(client_info->client_socket);
            free(client_info);
            continue;
        }
        
        // Create thread to handle this client
        if (pthread_create(&thread_id, NULL, handle_client, (void*)client_info) < 0) {
            perror("thread creation failed");
            SSL_free(client_info->ssl);
            close(client_info->client_socket);
            free(client_info);
            continue;
        }
        
        // Detach thread (will clean up automatically when done)
        pthread_detach(thread_id);
    }
    
    // This code is unreachable in this example, but included for completeness
    SSL_CTX_free(ssl_ctx);
    close(server_fd);
    
    return 0;
}