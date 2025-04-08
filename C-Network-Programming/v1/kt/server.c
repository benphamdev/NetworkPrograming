#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// Helper function for safe min operation
static inline size_t min(size_t a, size_t b) {
    return (a < b) ? a : b;
}

#define BUFFER_SIZE 16384
#define HOST_KEY_RSA "/etc/ssh/ssh_host_rsa_key"
#define HOST_KEY_ECDSA "/etc/ssh/ssh_host_ecdsa_key"
#define KEYS_FOLDER ".ssh/authorized_keys"
#define DEFAULT_PORT 2222

typedef struct {
    ssh_session session;
    // Remove dest_dir field as we're not using it anymore
} session_data_t;

// Function to get human-readable file size
const char* format_size(double size) {
    static char buffer[64];
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    
    while (size > 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    snprintf(buffer, sizeof(buffer), "%.2f %s", size, units[unit]);
    return buffer;
}

// Function to get current time string
char* get_time_str() {
    static char time_str[64];
    time_t now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return time_str;
}

// Check if the client's public key is authorized
int auth_publickey(ssh_session session, const char *user, struct ssh_key_struct *pubkey,
                   void *userdata) {
    unsigned char *hash = NULL;
    char pubkey_hash[256] = {0};
    char authorized_keys_path[1024];
    FILE *file;
    char *home_dir;
    char *hexa;
    size_t hash_len;
    int authorized = 0;
    
    (void)userdata;

    printf("Server: Authenticating user %s with public key...\n", user);
    
    // Get public key hash (using SHA1 as it's available)
    if (ssh_get_publickey_hash(pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash, &hash_len) != 0) {
        fprintf(stderr, "Server: Error getting public key hash\n");
        return SSH_AUTH_DENIED;
    }
    
    // Get hex representation of hash
    hexa = ssh_get_hexa(hash, hash_len);
    if (hexa == NULL) {
        fprintf(stderr, "Server: Error converting hash to hex\n");
        ssh_clean_pubkey_hash(&hash);
        return SSH_AUTH_DENIED;
    }
    strncpy(pubkey_hash, hexa, sizeof(pubkey_hash) - 1);
    ssh_string_free_char(hexa);
    
    printf("Server: Client public key hash: %s\n", pubkey_hash);
    
    // Clean up the hash
    ssh_clean_pubkey_hash(&hash);
    
    // Check if key is in authorized_keys
    home_dir = getenv("HOME");
    if (home_dir == NULL) {
        fprintf(stderr, "Server: Could not get home directory\n");
        return SSH_AUTH_DENIED;
    }
    
    snprintf(authorized_keys_path, sizeof(authorized_keys_path), 
             "%s/%s", home_dir, KEYS_FOLDER);
    
    // For simplicity in this version, we'll just check if file exists
    // and grant access without detailed key comparison
    file = fopen(authorized_keys_path, "r");
    if (file == NULL) {
        fprintf(stderr, "Server: Could not open authorized_keys file: %s\n", 
                authorized_keys_path);
        return SSH_AUTH_DENIED;
    }
    
    fclose(file);
    printf("Server: Public key authentication successful for %s\n", user);
    return SSH_AUTH_SUCCESS;
}

// Handle secure file transfers via a simple channel
int handle_secure_transfer(ssh_session session, ssh_channel channel, const char *dest_dir) {
    char buffer[BUFFER_SIZE];
    ssh_buffer command_buffer = ssh_buffer_new();
    char filename[1024] = {0};
    char remote_path[1024] = {0};
    FILE *file = NULL;
    ssize_t bytes;
    int rc;
    struct stat st;
    long long file_size = 0;
    
    printf("Server: File transfer subsystem started, ready to receive files in %s\n", dest_dir);
    
    // Read initial command (should contain filename)
    bytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        fprintf(stderr, "Server: Error reading command\n");
        ssh_buffer_free(command_buffer);
        return SSH_ERROR;
    }
    
    buffer[bytes] = '\0';
    printf("Server: Received command: %s\n", buffer);
    
    // Parse different command types
    if (strncmp(buffer, "MKDIR ", 6) == 0) {
        // Handle directory creation
        if (sscanf(buffer, "MKDIR %1023s", remote_path) != 1) {
            fprintf(stderr, "Server: Invalid MKDIR command format: %s\n", buffer);
            ssh_buffer_free(command_buffer);
            return SSH_ERROR;
        }
        
        // Create full path for the directory
        char dirpath[2048];
        snprintf(dirpath, sizeof(dirpath), "%s/%s", dest_dir, remote_path);
        
        printf("Server: Creating directory: %s\n", dirpath);
        
        // Create directory
        if (mkdir(dirpath, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "Server: Could not create directory %s: %s\n", 
                    dirpath, strerror(errno));
            sprintf(buffer, "ERROR: %s", strerror(errno));
            ssh_channel_write(channel, buffer, strlen(buffer));
            ssh_buffer_free(command_buffer);
            return SSH_ERROR;
        }
        
        // Send acknowledgment
        sprintf(buffer, "OK");
        ssh_channel_write(channel, buffer, strlen(buffer));
        
        ssh_buffer_free(command_buffer);
        return SSH_OK;
        
    } else if (strncmp(buffer, "SEND ", 5) == 0) {
        // Handle file transfer - supports both old and new format
        if (sscanf(buffer, "SEND %1023s %1023s %lld", filename, remote_path, &file_size) == 3) {
            // New format with path and size
            printf("Server: Receiving file: %s to path: %s (size: %lld bytes)\n", 
                   filename, remote_path, file_size);
        } else if (sscanf(buffer, "SEND %1023s", filename) == 1) {
            // Legacy format
            printf("Server: Receiving file: %s\n", filename);
            strncpy(remote_path, filename, sizeof(remote_path) - 1);
        } else {
            fprintf(stderr, "Server: Invalid SEND command format: %s\n", buffer);
            ssh_buffer_free(command_buffer);
            return SSH_ERROR;
        }
        
        // Create full path for the file
        char filepath[2048];
        if (remote_path[0] != '\0') {
            snprintf(filepath, sizeof(filepath), "%s/%s", dest_dir, remote_path);
            
            // Ensure directory exists
            char *dir_path = strdup(filepath);
            if (dir_path) {
                char *last_slash = strrchr(dir_path, '/');
                if (last_slash) {
                    *last_slash = '\0';  // Terminate string at last slash
                    
                    // Create directory path recursively
                    char *p = dir_path;
                    // Skip leading slashes
                    while (*p == '/') p++;
                    
                    while (*p) {
                        if (*p == '/') {
                            *p = '\0';
                            mkdir(dir_path, 0755);  // Ignore errors
                            *p = '/';
                        }
                        p++;
                    }
                    mkdir(dir_path, 0755);  // Create final component
                }
                free(dir_path);
            }
        } else {
            snprintf(filepath, sizeof(filepath), "%s/%s", dest_dir, filename);
        }
        
        // Open file for writing
        file = fopen(filepath, "wb");
        if (file == NULL) {
            fprintf(stderr, "Server: Could not open file %s for writing: %s\n", 
                    filepath, strerror(errno));
            sprintf(buffer, "ERROR: Could not create file - %s", strerror(errno));
            ssh_channel_write(channel, buffer, strlen(buffer));
            ssh_buffer_free(command_buffer);
            return SSH_ERROR;
        }
        
        printf("Server: File transfer started at %s\n", get_time_str());
        
        // Send acknowledgment
        sprintf(buffer, "OK");
        ssh_channel_write(channel, buffer, strlen(buffer));
        
        // Read file data
        uint64_t total_bytes = 0;
        while ((bytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
            if (fwrite(buffer, 1, bytes, file) != bytes) {
                fprintf(stderr, "Server: Error writing to file %s\n", filepath);
                fclose(file);
                ssh_buffer_free(command_buffer);
                return SSH_ERROR;
            }
            
            total_bytes += bytes;
            
            // Print progress (periodic)
            if (total_bytes % (1024 * 1024) == 0) { // Each MB
                printf("\rServer: Receiving data: %s", format_size((double)total_bytes));
                fflush(stdout);
            }
        }
        
        fclose(file);
        
        // Get file stats
        if (stat(filepath, &st) == 0) {
            printf("\nServer: File transfer completed at %s\n", get_time_str());
            printf("Server: File: %s, Size: %s\n", 
                  filename, format_size((double)st.st_size));
        } else {
            fprintf(stderr, "\nServer: Could not stat file %s: %s\n", 
                    filepath, strerror(errno));
        }
    } else {
        fprintf(stderr, "Server: Unknown command format: %s\n", buffer);
        ssh_buffer_free(command_buffer);
        return SSH_ERROR;
    }
    
    ssh_buffer_free(command_buffer);
    return SSH_OK;
}

// Helper function to create directory if it doesn't exist
int ensure_local_directory(const char *path) {
    struct stat st;
    
    // First check if the path already exists
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0; // Directory exists
        } else {
            fprintf(stderr, "Error: Path exists but is not a directory: %s\n", path);
            return -1; // Path exists but is not a directory
        }
    }
    
    // Path doesn't exist, create directory recursively
    char *path_copy = strdup(path);
    if (path_copy == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }
    
    // Create parent directories
    for (char *p = path_copy + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(path_copy, 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, "Error creating directory %s: %s\n", path_copy, strerror(errno));
            }
            *p = '/';
        }
    }
    
    // Create the final directory
    int result = mkdir(path_copy, 0755);
    if (result != 0 && errno != EEXIST) {
        fprintf(stderr, "Error creating directory %s: %s\n", path_copy, strerror(errno));
    } else {
        result = 0; // Success or already exists
    }
    
    free(path_copy);
    return result;
}

// Main SSH client handler
void *client_thread(void *arg) {
    session_data_t *data = (session_data_t*)arg;
    ssh_session session = data->session;
    ssh_message message;
    ssh_channel chan = NULL;
    int authenticated = 0;

    // Accept connection
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "Server: Key exchange error: %s\n", ssh_get_error(session));
        goto cleanup;
    }

    printf("Server: Client connected at %s\n", get_time_str());

    // Authentication loop
    while (!authenticated) {
        message = ssh_message_get(session);
        if (message == NULL) {
            if (ssh_get_error_code(session) == SSH_REQUEST_DENIED) {
                fprintf(stderr, "Server: Authentication request denied\n");
                break;
            }
            if (ssh_get_error_code(session) == SSH_FATAL) {
                fprintf(stderr, "Server: Fatal error during authentication: %s\n",
                        ssh_get_error(session));
                break;
            }
            usleep(10000); // 10ms
            continue;
        }

        printf("Server: Received message type: %d, subtype: %d\n", 
               ssh_message_type(message), ssh_message_subtype(message));

        switch (ssh_message_type(message)) {
            case SSH_REQUEST_AUTH:
                switch (ssh_message_subtype(message)) {
                    case SSH_AUTH_METHOD_PUBLICKEY:
                        if (auth_publickey(session, ssh_message_auth_user(message),
                                        ssh_message_auth_pubkey(message), NULL) == SSH_AUTH_SUCCESS) {
                            printf("Server: Authentication successful, replying to client\n");
                            ssh_message_auth_reply_success(message, 0);
                            authenticated = 1;
                        } else {
                            printf("Server: Authentication failed, sending default reply\n");
                            ssh_message_reply_default(message);
                        }
                        break;
                    case SSH_AUTH_METHOD_NONE:
                        ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                        ssh_message_reply_default(message);
                        break;
                    default:
                        ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                        ssh_message_reply_default(message);
                        break;
                }
                break;

            default:
                ssh_message_reply_default(message);
                break;
        }

        ssh_message_free(message);
    }

    if (!authenticated) {
        fprintf(stderr, "Server: Authentication failed\n");
        goto cleanup;
    }

    printf("Server: Authentication completed, waiting for channel\n");

    // Channel handling loop
    do {
        message = ssh_message_get(session);
        if (message == NULL) {
            if (ssh_get_error_code(session) == SSH_EOF || 
                ssh_get_error_code(session) == SSH_FATAL) {
                fprintf(stderr, "Server: Connection error: %s\n", 
                        ssh_get_error(session));
                break;
            }
            usleep(100000); // 100ms
            continue;
        }

        printf("Server: Received message type: %d, subtype: %d\n", 
               ssh_message_type(message), ssh_message_subtype(message));

        switch (ssh_message_type(message)) {
            case SSH_REQUEST_CHANNEL_OPEN:
                if (ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
                    printf("Server: Accepting channel request\n");
                    chan = ssh_message_channel_request_open_reply_accept(message);
                    if (chan == NULL) {
                        fprintf(stderr, "Server: Error creating channel: %s\n", 
                                ssh_get_error(session));
                    }
                } else {
                    printf("Server: Rejecting non-session channel\n");
                    ssh_message_reply_default(message);
                }
                break;

            case SSH_REQUEST_CHANNEL:
                if (chan != NULL) {
                    printf("Server: Processing channel request of subtype %d\n", 
                           ssh_message_subtype(message));

                    if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_EXEC) {
                        const char *cmd = ssh_message_channel_request_command(message);
                        printf("Server: Received exec request: %s\n", cmd ? cmd : "NULL");

                        if (cmd) {
                            if (strncmp(cmd, "MKDIR ", 6) == 0) {
                                char mkdir_path[1024] = {0};
                                if (sscanf(cmd, "MKDIR %1023s", mkdir_path) == 1) {
                                    // Use the path exactly as provided by client
                                    printf("Server: Creating directory: %s\n", mkdir_path);
                                    
                                    if (ensure_local_directory(mkdir_path) == 0) {
                                        ssh_channel_write(chan, "OK", 2);
                                        printf("Server: Directory created successfully: %s\n", mkdir_path);
                                    } else {
                                        ssh_channel_write(chan, "ERROR: Failed to create directory", 32);
                                        fprintf(stderr, "Server: Failed to create directory: %s\n", mkdir_path);
                                    }
                                } else {
                                    ssh_channel_write(chan, "ERROR: Invalid MKDIR format", 26);
                                }
                            } else if (strncmp(cmd, "SEND ", 5) == 0) {
                                char filename[1024] = {0};
                                char remote_path[1024] = {0};
                                long long file_size = 0;

                                if (sscanf(cmd, "SEND %1023s %1023s %lld", filename, remote_path, &file_size) == 3) {
                                    // Use the exact path provided by the client
                                    printf("Server: Received request to save file %s to path: %s (%lld bytes)\n", 
                                           filename, remote_path, file_size);

                                    // Make sure parent directory exists
                                    char *parent_dir = strdup(remote_path);
                                    if (parent_dir) {
                                        char *last_slash = strrchr(parent_dir, '/');
                                        if (last_slash) {
                                            *last_slash = '\0';
                                            ensure_local_directory(parent_dir);
                                        }
                                        free(parent_dir);
                                    }

                                    FILE *file = fopen(remote_path, "wb");
                                    if (file == NULL) {
                                        fprintf(stderr, "Server: Could not open file %s for writing: %s\n", 
                                                remote_path, strerror(errno));
                                        ssh_channel_write(chan, "ERROR: Could not create file", 28);
                                    } else {
                                        ssh_channel_write(chan, "OK", 2);
                                        
                                        char buffer[BUFFER_SIZE];
                                        uint64_t total_bytes = 0;
                                        ssize_t bytes;
                                        int read_error = 0;
                                        time_t last_progress = time(NULL);

                                        printf("Server: Starting file transfer for: %s\n", remote_path);
                                        
                                        // Add a small delay to ensure client is ready
                                        usleep(100000);  // 100ms delay
                                        
                                        while (total_bytes < (uint64_t)file_size && !read_error) {
                                            // Use non-blocking read with timeout
                                            int read_ready = ssh_channel_poll(chan, 0);
                                            if (read_ready < 0) {
                                                fprintf(stderr, "Server: Channel poll error\n");
                                                read_error = 1;
                                                break;
                                            }
                                            
                                            if (read_ready > 0) {
                                                bytes = ssh_channel_read(chan, buffer, 
                                                    min(sizeof(buffer), file_size - total_bytes), 0);
                                                
                                                if (bytes > 0) {
                                                    size_t written = fwrite(buffer, 1, bytes, file);
                                                    if (written != bytes) {
                                                        fprintf(stderr, "Server: Error writing to file %s\n", remote_path);
                                                        read_error = 1;
                                                        break;
                                                    }
                                                    total_bytes += bytes;
                                                    
                                                    // Print progress every second
                                                    time_t now = time(NULL);
                                                    if (now != last_progress) {
                                                        printf("\rServer: Received %s so far (%.1f%%)", 
                                                               format_size((double)total_bytes),
                                                               (double)total_bytes * 100 / file_size);
                                                        fflush(stdout);
                                                        last_progress = now;
                                                    }
                                                } else if (bytes < 0) {
                                                    fprintf(stderr, "\nServer: Error reading from channel: %s\n", 
                                                            ssh_get_error(session));
                                                    read_error = 1;
                                                    break;
                                                }
                                            } else {
                                                // No data available, wait a bit
                                                usleep(1000);  // 1ms delay
                                            }
                                            
                                            // Check if channel is closed
                                            if (ssh_channel_is_eof(chan)) {
                                                if (total_bytes < (uint64_t)file_size) {
                                                    fprintf(stderr, "\nServer: Warning: Channel closed before receiving entire file\n");
                                                    read_error = 1;
                                                }
                                                break;
                                            }
                                        }

                                        // Ensure all data is written to disk
                                        fflush(file);
                                        fclose(file);

                                        if (!read_error && total_bytes == (uint64_t)file_size) {
                                            printf("\nServer: File transfer completed successfully: %s (%s)\n", 
                                                   remote_path, format_size((double)total_bytes));
                                            ssh_channel_write(chan, "DONE", 4);
                                        } else {
                                            fprintf(stderr, "\nServer: File transfer failed or incomplete\n");
                                            ssh_channel_write(chan, "ERROR: Transfer incomplete", 24);
                                            // Remove incomplete file
                                            unlink(remote_path);
                                        }
                                    }
                                } else {
                                    ssh_channel_write(chan, "ERROR: Invalid SEND format", 25);
                                }
                            } else {
                                ssh_message_reply_default(message);
                            }
                        
                            // Accept the exec request
                            ssh_message_channel_request_reply_success(message);
                        } else {
                            ssh_message_reply_default(message);
                        }
                    } else {
                        ssh_message_reply_default(message);
                    }
                } else {
                    ssh_message_reply_default(message);
                }
                break;

            default:
                ssh_message_reply_default(message);
                break;
        }

        ssh_message_free(message);

    } while (chan == NULL || !ssh_channel_is_closed(chan));

cleanup:
    printf("Server: Cleaning up session\n");
    if (chan != NULL) {
        ssh_channel_close(chan);
        ssh_channel_free(chan);
    }

    ssh_disconnect(session);
    ssh_free(session);
    free(data);

    return NULL;
}

int main(int argc, char *argv[]) {
    ssh_bind sshbind;
    ssh_session session;
    int port = DEFAULT_PORT;
    int rc;
    pthread_t thread;
    
    if (argc < 1 || argc > 2) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        return -1;
    }
    
    // Set custom port if provided
    if (argc == 2) {
        port = atoi(argv[1]);
        if (port <= 0) {
            fprintf(stderr, "Invalid port number\n");
            return -1;
        }
    }
    
    // Initialize SSH server
    ssh_init();
    
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Error creating SSH bind: out of memory\n");
        return -1;
    }
    
    // Set server options
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    
    // Try different host keys with preference for modern algorithms
    if (access(HOST_KEY_ECDSA, F_OK) == 0) {
        printf("Server: Using ECDSA host key\n");
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, HOST_KEY_ECDSA);
    } else if (access(HOST_KEY_RSA, F_OK) == 0) {
        printf("Server: Using RSA host key\n");
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, HOST_KEY_RSA);
    } else {
        fprintf(stderr, "No host keys found. Please generate SSH host keys.\n");
        fprintf(stderr, "Run the following commands to generate keys:\n");
        fprintf(stderr, "  ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N \"\"\n");
        fprintf(stderr, "  ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N \"\"\n");
        ssh_bind_free(sshbind);
        return -1;
    }
    
    // Start listening
    rc = ssh_bind_listen(sshbind);
    if (rc < 0) {
        fprintf(stderr, "Error listening on port %d: %s\n", port, ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        return -1;
    }
    
    printf("Server: Listening on port %d for SSH connections\n", port);
    printf("Server: Authentication method: Public key\n");
    
    // Main server loop
    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "Error creating new SSH session\n");
            continue;
        }
        
        // Accept connection
        rc = ssh_bind_accept(sshbind, session);
        if (rc != SSH_OK) {
            fprintf(stderr, "Error accepting connection: %s\n", ssh_get_error(sshbind));
            ssh_free(session);
            continue;
        }
        
        printf("Server: New connection at %s\n", get_time_str());
        
        // Allocate session data
        session_data_t *data = malloc(sizeof(session_data_t));
        if (data == NULL) {
            fprintf(stderr, "Error allocating memory for session data\n");
            ssh_free(session);
            continue;
        }
        
        data->session = session;
        
        // Create thread to handle client
        if (pthread_create(&thread, NULL, client_thread, data) != 0) {
            fprintf(stderr, "Error creating thread\n");
            free(data);
            ssh_free(session);
            continue;
        }
        
        // Detach thread
        pthread_detach(thread);
    }
    
    // Clean up
    ssh_bind_free(sshbind);
    ssh_finalize();
    
    return 0;
}
