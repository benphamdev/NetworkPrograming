#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_FILE_SIZE 65536  // Maximum file size to read (64KB)

// HTTP response headers
const char* HTTP_200_OK = "HTTP/1.1 200 OK\r\n";
const char* HTTP_404_NOT_FOUND = "HTTP/1.1 404 Not Found\r\n";
const char* CONTENT_TYPE_HTML = "Content-Type: text/html\r\n";
const char* CONTENT_TYPE_JSON = "Content-Type: application/json\r\n";

// Function to read file content
char* read_file(const char* filename, size_t* content_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Failed to open file %s: %s\n", filename, strerror(errno));
        return NULL;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size > MAX_FILE_SIZE) {
        printf("File %s is too large (%ld bytes)\n", filename, file_size);
        fclose(file);
        return NULL;
    }
    
    // Allocate memory for file content
    char* content = (char*)malloc(file_size + 1);
    if (!content) {
        printf("Failed to allocate memory for file %s\n", filename);
        fclose(file);
        return NULL;
    }
    
    // Read file content
    size_t bytes_read = fread(content, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != file_size) {
        printf("Failed to read entire file %s\n", filename);
        free(content);
        return NULL;
    }
    
    // Null-terminate the string
    content[bytes_read] = '\0';
    *content_size = bytes_read;
    
    return content;
}

// Function to parse HTTP headers with query string support
void parse_http_headers(char* buffer, char* method, char* path, char* query_string) {
    // Initialize query string to empty
    query_string[0] = '\0';
    
    // Extract method and full URL
    char* token = strtok(buffer, " \t\r\n");
    if (token) {
        strcpy(method, token);
        token = strtok(NULL, " \t\r\n");
        if (token) {
            // Extract path and query string
            char* question_mark = strchr(token, '?');
            if (question_mark) {
                // URL contains query string
                int path_length = question_mark - token;
                strncpy(path, token, path_length);
                path[path_length] = '\0';
                strcpy(query_string, question_mark + 1);
            } else {
                // No query string
                strcpy(path, token);
            }
        }
    }
}

// Structure to pass client information to the thread
typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
} client_info_t;

void *handle_request(void *arg) {
    client_info_t *client_info = (client_info_t *)arg;
    int client_socket = client_info->client_socket;
    struct sockaddr_in client_addr = client_info->client_addr;
    char buffer[BUFFER_SIZE], buffer1[BUFFER_SIZE];
    char method[10];
    char path[256];
    char query_string[256];
    int bytes_read;

    // Free the client info structure
    free(arg);

    // Get client IP and port
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    // Read HTTP request
    bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_read < 0) {
        perror("read");
        close(client_socket);
        return NULL;
    }
    buffer[bytes_read] = '\0';
    strcpy(buffer1, buffer);
    
    // Parse HTTP headers with query string support
    parse_http_headers(buffer1, method, path, query_string);
    printf("Received %s request for %s", method, path);
    if (query_string[0] != '\0') {
        printf(" with query string: %s", query_string);
    }
    printf(" from %s:%d\n", client_ip, client_port);

    // Handle different HTTP methods and paths
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
            // Serve index.html from file
            size_t content_size;
            char* content = read_file("index.html", &content_size);
            
            if (content) {
                // File found, send it
                char response_header[512];
                sprintf(response_header, "%s%sContent-Length: %zu\r\n\r\n",
                        HTTP_200_OK,
                        CONTENT_TYPE_HTML,
                        content_size);
                
                // Send header
                write(client_socket, response_header, strlen(response_header));
                
                // Send content
                write(client_socket, content, content_size);
                
                // Free allocated memory
                free(content);
            } else {
                // File not found, send default message
                const char* not_found = "<html><body><h1>Error loading index.html</h1><p>Could not find or read the index.html file.</p></body></html>";
                char response[BUFFER_SIZE];
                sprintf(response, "%s%sContent-Length: %lu\r\n\r\n%s",
                        HTTP_404_NOT_FOUND,
                        CONTENT_TYPE_HTML,
                        strlen(not_found),
                        not_found);
                write(client_socket, response, strlen(response));
            }
        }
        else if (strcmp(path, "/hello") == 0) {
            // Handle /hello with optional query params
            char response_html[1024];
            if (query_string[0] != '\0') {
                sprintf(response_html, 
                        "<html><body>"
                        "<h1>Hello there!</h1>"
                        "<p>You sent query string: %s</p>"
                        "</body></html>", 
                        query_string);
            } else {
                sprintf(response_html, 
                        "<html><body>"
                        "<h1>Hello there!</h1>"
                        "<p>No query string provided</p>"
                        "</body></html>");
            }
            
            char response[BUFFER_SIZE];
            sprintf(response, "%s%sContent-Length: %lu\r\n\r\n%s",
                    HTTP_200_OK,
                    CONTENT_TYPE_HTML,
                    strlen(response_html),
                    response_html);
            write(client_socket, response, strlen(response));
        }
        else if (strcmp(path, "/api/data") == 0) {
            // Sample JSON response
            const char* json_data = "{\"message\": \"Hello from the server!\"}";
            char response[BUFFER_SIZE];
            sprintf(response, "%s%sContent-Length: %lu\r\n\r\n%s",
                    HTTP_200_OK,
                    CONTENT_TYPE_JSON,
                    strlen(json_data),
                    json_data);
            write(client_socket, response, strlen(response));
        }
        else {
            // 404 Not Found
            const char* not_found = "<html><body><h1>404 Not Found</h1></body></html>";
            char response[BUFFER_SIZE];
            sprintf(response, "%s%sContent-Length: %lu\r\n\r\n%s",
                    HTTP_404_NOT_FOUND,
                    CONTENT_TYPE_HTML,
                    strlen(not_found),
                    not_found);
            write(client_socket, response, strlen(response));
        }
    }
    else if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/api/data") == 0) {
            // Find the start of JSON data in the request
            char* json_start = strstr(buffer, "\r\n\r\n");
            if (json_start) {
                json_start += 4; // Skip \r\n\r\n
                printf("Received JSON data: %s\n", json_start);

                // Send response
                const char* response_json = "{\"status\": \"success\"}";
                char response[BUFFER_SIZE];
                sprintf(response, "%s%sContent-Length: %lu\r\n\r\n%s",
                        HTTP_200_OK,
                        CONTENT_TYPE_JSON,
                        strlen(response_json),
                        response_json);
                write(client_socket, response, strlen(response));
            }
        }
    }
    
    close(client_socket);
    return NULL;
}

int main() {
    int server_socket, new_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    pthread_t tid;

    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Bind socket to address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 10) == -1) {
        perror("listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept connections in a loop
    while (1) {
        if ((new_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
            perror("accept");
            continue;
        }

        printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Allocate memory for the client info structure
        client_info_t *client_info = malloc(sizeof(client_info_t));
        if (!client_info) {
            perror("malloc");
            close(new_socket);
            continue;
        }

        // Populate the client info structure
        client_info->client_socket = new_socket;
        client_info->client_addr = client_addr;

        // Create a new thread to handle the client
        if (pthread_create(&tid, NULL, handle_request, client_info) != 0) {
            perror("pthread_create");
            free(client_info);
            close(new_socket);
        }

        // Detach the thread to allow it to clean up independently
        pthread_detach(tid);
    }

    // Close the server socket (this will never be reached in this example)
    close(server_socket);

    return 0;
}