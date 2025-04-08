#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>  // Add this to define O_WRONLY, O_RDONLY, O_CREAT, O_TRUNC
#include <dirent.h> // For directory operations
#include <errno.h>  // Add this for errno
#include <time.h>

#define BUFFER_SIZE 4096

// Forward declarations
ssh_session duplicate_ssh_session(ssh_session original);

// Helper function to get human-readable file size
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

// Helper function to get current time string
char* get_time_str() {
    static char time_str[64];
    time_t now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return time_str;
}

// Helper function to check if path is a directory
int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return S_ISDIR(st.st_mode);
}

// Function to create remote directory
int create_remote_directory(sftp_session sftp, const char *remote_dir) {
    int rc = sftp_mkdir(sftp, remote_dir, 0755);
    if (rc != SSH_OK) {
        if (sftp_get_error(sftp) == SSH_FX_FILE_ALREADY_EXISTS) {
            // Directory already exists, not an error
            return SSH_OK;
        }
        fprintf(stderr, "Error creating remote directory %s (error code: %d)\n", 
                remote_dir, sftp_get_error(sftp));
        return rc;
    }
    return SSH_OK;
}

// Modified upload function using exec channel instead of SFTP
int upload_file(ssh_session session, const char *local_path, const char *remote_path) {
    ssh_channel channel;
    FILE *local_file;
    int rc;
    char buffer[BUFFER_SIZE];
    size_t nread;
    struct stat st;
    time_t start_time, end_time;
    uint64_t total_written = 0;

    // Get file stats to determine size
    if (stat(local_path, &st) != 0) {
        fprintf(stderr, "Error getting file stats: %s\n", local_path);
        return -1;
    }
    uint64_t file_size = st.st_size;

    // Open local file
    local_file = fopen(local_path, "rb");
    if (local_file == NULL) {
        fprintf(stderr, "Error opening local file: %s\n", local_path);
        return -1;
    }

    // Create a channel
    channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "Error creating channel: %s\n", ssh_get_error(session));
        fclose(local_file);
        return -1;
    }

    // Open session channel
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error opening session: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        fclose(local_file);
        return -1;
    }

    // Create command with our custom protocol format
    char command[2048];
    const char *filename = strrchr(local_path, '/');
    if (filename == NULL)
        filename = local_path;
    else
        filename++; // Skip the slash
    
    // Just send the full remote path and size
    snprintf(command, sizeof(command), "SEND %s %s %lld", filename, remote_path, (long long)file_size);
    
    // Execute the command
    printf("Sending exec command: %s\n", command);
    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error executing remote command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        fclose(local_file);
        return -1;
    }
    
    // Wait for acknowledgment with timeout
    time_t start_wait = time(NULL);
    while (time(NULL) - start_wait < 10) { // 10 second timeout
        rc = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
        if (rc > 0) {
            buffer[rc] = '\0';
            if (strncmp(buffer, "OK", 2) == 0) {
                break;
            } else if (strncmp(buffer, "ERROR", 5) == 0) {
                fprintf(stderr, "Server rejected file transfer: %s\n", buffer);
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                fclose(local_file);
                return -1;
            }
        }
        usleep(100000); // 100ms delay between retries
    }

    if (time(NULL) - start_wait >= 10) {
        fprintf(stderr, "Timeout waiting for server acknowledgment\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        fclose(local_file);
        return -1;
    }

    printf("Uploading: %s (%s) started at %s\n", 
            local_path, format_size((double)file_size), get_time_str());
    
    start_time = time(NULL);

    // Transfer file data in smaller chunks to prevent data loss
    const size_t chunk_size = BUFFER_SIZE;
    while ((nread = fread(buffer, 1, chunk_size, local_file)) > 0) {
        size_t bytes_sent = 0;
        
        // Make sure we send the entire chunk, even if ssh_channel_write doesn't write it all at once
        while (bytes_sent < nread) {
            ssize_t nwritten = ssh_channel_write(channel, buffer + bytes_sent, nread - bytes_sent);
            
            if (nwritten <= 0) {
                fprintf(stderr, "Error writing to channel: %s\n", ssh_get_error(session));
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                fclose(local_file);
                return -1;
            }
            
            bytes_sent += nwritten;
        }
        
        total_written += nread;
        
        // Update progress
        printf("\rProgress: %.2f%% (%s/%s)", 
            (float)total_written / file_size * 100,
            format_size((double)total_written), 
            format_size((double)file_size));
        fflush(stdout);
    }
    
    end_time = time(NULL);
    double elapsed = difftime(end_time, start_time);
    
    // Remove ssh_channel_flush call and ensure proper channel cleanup
    printf("\nUpload complete: %s (%s) - Took %.1f seconds (%.2f MB/s)\n", 
            local_path, format_size((double)file_size), 
            elapsed, (file_size/1024.0/1024.0)/elapsed);

    fclose(local_file);
    
    // After transfer completion, wait for final acknowledgment
    start_wait = time(NULL);
    while (time(NULL) - start_wait < 5) { // 5 second timeout
        rc = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
        if (rc > 0) {
            buffer[rc] = '\0';
            if (strncmp(buffer, "DONE", 4) == 0) {
                printf("Server confirmed successful transfer\n");
                break;
            } else if (strncmp(buffer, "ERROR", 5) == 0) {
                fprintf(stderr, "Server reported error: %s\n", buffer);
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return -1;
            }
        }
        usleep(100000);
    }

    // Make sure server has processed all the data before closing
    ssh_channel_send_eof(channel);
    
    // Wait a moment to ensure data is processed by the server
    usleep(100000); // 100ms
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return 0;
}

// Function to download file from remote server using SFTP
/*
    The download_file function is similar to the upload_file function, but in reverse.
    It opens a remote file for reading and a local file for writing, then reads data from the remote file and writes it to the local file.
    The file size is determined by getting the file attributes using sftp_fstat, and the download progress is displayed as a percentage.
*/
int download_file(ssh_session session, const char *remote_path, const char *local_path) {
    sftp_session sftp;
    sftp_file file;
    FILE *local_file;
    int rc;
    char buffer[BUFFER_SIZE];

    // Initialize SFTP session
    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error creating SFTP session: %s\n", ssh_get_error(session));
        return -1;
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    // Open remote file for reading
    file = sftp_open(sftp, remote_path, O_RDONLY, 0);
    if (file == NULL) {
        fprintf(stderr, "Error opening remote file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    // Get file attributes to determine file size
    sftp_attributes attrs = sftp_fstat(file);
    if (attrs == NULL) {
        fprintf(stderr, "Error getting file attributes: %s\n", ssh_get_error(session));
        sftp_close(file);
        sftp_free(sftp);
        return -1;
    }

    uint64_t file_size = attrs->size;
    sftp_attributes_free(attrs);

    // Open local file for writing
    local_file = fopen(local_path, "wb");
    if (local_file == NULL) {
        fprintf(stderr, "Error opening local file: %s\n", local_path);
        sftp_close(file);
        sftp_free(sftp);
        return -1;
    }

    // Read file data
    uint64_t total_read = 0;
    ssize_t nread;
    while ((nread = sftp_read(file, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, nread, local_file);
        total_read += nread;
        printf("\rDownloading... %.2f%%", (float)total_read / file_size * 100);
        fflush(stdout);
    }

    if (nread < 0) {
        fprintf(stderr, "\nError reading file: %s\n", ssh_get_error(session));
        fclose(local_file);
        sftp_close(file);
        sftp_free(sftp);
        return -1;
    }

    printf("\nDownload complete\n");

    fclose(local_file);
    sftp_close(file);
    sftp_free(sftp);
    return 0;
}

// Function to create remote directory using custom protocol
int create_remote_directory_custom(ssh_session session, const char *remote_dir) {
    ssh_channel channel;
    int rc;
    char buffer[BUFFER_SIZE];
    
    // Create a channel
    channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "Error creating channel: %s\n", ssh_get_error(session));
        return -1;
    }
    
    // Open session channel
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error opening session: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return -1;
    }
    
    // Create command for directory creation
    char command[2048];
    snprintf(command, sizeof(command), "MKDIR %s", remote_dir);
    
    // Execute the command
    printf("Creating directory: %s\n", remote_dir);
    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error executing remote command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    // Wait for acknowledgment with retry mechanism
    int retries = 0;
    const int max_retries = 5;
    
    while (retries < max_retries) {
        rc = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
        
        if (rc > 0) {
            buffer[rc] = '\0';
            if (strncmp(buffer, "OK", 2) == 0) {
                printf("Directory created successfully: %s\n", remote_dir);
                break; // Successfully created
            } else {
                fprintf(stderr, "Server response: %s\n", buffer);
                if (strstr(buffer, "EEXIST") != NULL) {
                    printf("Directory already exists: %s\n", remote_dir);
                    break; // Directory exists, also success
                }
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return -1;
            }
        } else if (rc == 0) {
            // No data yet, wait and retry
            usleep(100000); // 100ms
            retries++;
        } else {
            // Error
            fprintf(stderr, "Error: Server did not acknowledge directory creation (rc=%d)\n", rc);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return -1;
        }
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    // Even if we failed to get acknowledgment, assume it's OK (might be ready)
    return 0;
}

// Simplified function to upload a directory
int upload_directory(ssh_session session, const char *local_dir, const char *remote_dir) {
    DIR *dir;
    struct dirent *entry;
    int total_files = 0;
    int successful_files = 0;
    
    printf("Uploading directory %s to %s\n", local_dir, remote_dir);
    
    // First make sure the remote directory exists
    create_remote_directory_custom(session, remote_dir);
    
    // Open the local directory
    dir = opendir(local_dir);
    if (dir == NULL) {
        fprintf(stderr, "Error opening local directory: %s\n", local_dir);
        return -1;
    }
    
    // First, count number of files to upload
    DIR *count_dir = opendir(local_dir);
    if (count_dir != NULL) {
        struct dirent *count_entry;
        while ((count_entry = readdir(count_dir)) != NULL) {
            if (strcmp(count_entry->d_name, ".") != 0 && strcmp(count_entry->d_name, "..") != 0) {
                total_files++;
            }
        }
        closedir(count_dir);
    }
    
    printf("Found %d items in directory %s\n", total_files, local_dir);
    
    // First, create all subdirectories
    rewinddir(dir);
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char local_path[1024];
        char remote_path[1024];
        snprintf(local_path, sizeof(local_path), "%s/%s", local_dir, entry->d_name);
        snprintf(remote_path, sizeof(remote_path), "%s/%s", remote_dir, entry->d_name);
        
        if (is_directory(local_path)) {
            printf("Creating remote directory: %s\n", remote_path);
            create_remote_directory_custom(session, remote_path);
        }
    }
    
    // Then upload all files and recursively process subdirectories
    rewinddir(dir);
    int file_counter = 0;
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        file_counter++;
        char local_path[1024];
        char remote_path[1024];
        snprintf(local_path, sizeof(local_path), "%s/%s", local_dir, entry->d_name);
        snprintf(remote_path, sizeof(remote_path), "%s/%s", remote_dir, entry->d_name);
        
        if (is_directory(local_path)) {
            // Process subdirectory recursively
            printf("[%d/%d] Processing directory: %s\n", file_counter, total_files, entry->d_name);
            int rc = upload_directory(session, local_path, remote_path);
            if (rc == 0) {
                successful_files++;
            } else {
                fprintf(stderr, "Failed to process directory: %s\n", local_path);
            }
        } else {
            // Upload the file - No retries as requested
            printf("[%d/%d] Uploading file: %s\n", file_counter, total_files, entry->d_name);
            int rc = upload_file(session, local_path, remote_path);
            if (rc == 0) {
                successful_files++;
            } else {
                fprintf(stderr, "Failed to upload file: %s\n", local_path);
                // Don't retry on failure
            }
        }
    }
    
    closedir(dir);
    printf("Directory upload complete: %d/%d items processed successfully\n", 
           successful_files, total_files);
    
    return (successful_files > 0) ? 0 : -1; // Consider success if at least one file uploaded
}

// Helper to create a duplicate SSH session using the same credentials
ssh_session duplicate_ssh_session(ssh_session original) {
    ssh_session new_session = ssh_new();
    if (new_session == NULL) {
        return NULL;
    }
    
    // Copy connection parameters from original session
    char *host = NULL;
    char *user = NULL;
    char *identity = NULL;
    unsigned int port = 22;
    int verbosity = SSH_LOG_WARNING;
    
    // Get parameters from original session - with proper type handling
    if (ssh_options_get_port(original, &port) != SSH_OK) {
        port = 22; // Default if we can't get it
    }
    
    // For string options, we need temporary variables
    if (ssh_options_get(original, SSH_OPTIONS_HOST, &host) != SSH_OK) {
        host = NULL;
    }
    
    if (ssh_options_get(original, SSH_OPTIONS_USER, &user) != SSH_OK) {
        user = NULL;
    }
    
    if (ssh_options_get(original, SSH_OPTIONS_IDENTITY, &identity) != SSH_OK) {
        identity = NULL;
    }
    
    // Set longer timeout options to prevent quick disconnections
    int timeout = 60; // 60 seconds
    ssh_options_set(new_session, SSH_OPTIONS_TIMEOUT, &timeout);
    
    // Set same parameters on new session
    if (host) {
        ssh_options_set(new_session, SSH_OPTIONS_HOST, host);
        free(host); // Free the memory allocated by ssh_options_get
    }
    
    ssh_options_set(new_session, SSH_OPTIONS_PORT, &port);
    
    if (user) {
        ssh_options_set(new_session, SSH_OPTIONS_USER, user);
        free(user);
    }
    
    ssh_options_set(new_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    
    if (identity) {
        ssh_options_set(new_session, SSH_OPTIONS_IDENTITY, identity);
        free(identity);
    }
    
    // Set TCP keepalive in a different way
    // First try SSH_OPTIONS_NODELAY which helps with responsiveness
    int yes = 1;
    ssh_options_set(new_session, SSH_OPTIONS_NODELAY, &yes);
    
    // Connect
    if (ssh_connect(new_session) != SSH_OK) {
        ssh_free(new_session);
        return NULL;
    }
    
    // For some versions of libssh, we can enable keepalive directly on the socket
    // using ssh_set_keepalive if it's available
    #ifdef HAVE_LIBSSH_SET_KEEPALIVE
    ssh_set_keepalive(new_session, 1, 60);  // Enable with 60-second interval
    #endif
    
    // Authenticate
    int rc = ssh_userauth_publickey_auto(new_session, NULL, NULL);
    if (rc != SSH_AUTH_SUCCESS) {
        char *passphrase = NULL; // No passphrase for now
        ssh_key privkey = NULL;
        
        // Try to get the identity file path and use it directly
        if (identity && ssh_pki_import_privkey_file(identity, passphrase, NULL, NULL, &privkey) == SSH_OK) {
            rc = ssh_userauth_publickey(new_session, NULL, privkey);
            ssh_key_free(privkey);
        }
        
        if (rc != SSH_AUTH_SUCCESS) {
            ssh_disconnect(new_session);
            ssh_free(new_session);
            return NULL;
        }
    }
    
    return new_session;
}

// Function to ensure local directory exists
int ensure_local_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0; // Directory exists
        } else {
            return -1; // Path exists but is not a directory
        }
    }
    
    // Create directory with permissions 0755
    if (mkdir(path, 0755) != 0) {
        fprintf(stderr, "Error creating directory %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

// Function to recursively download a directory
int download_directory(ssh_session session, const char *remote_dir, const char *local_dir) {
    sftp_session sftp;
    sftp_dir dir;
    sftp_attributes attributes;
    int rc;

    // Ensure local directory exists
    if (ensure_local_directory(local_dir) != 0) {
        return -1;
    }

    // Initialize SFTP session
    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error creating SFTP session: %s\n", ssh_get_error(session));
        return -1;
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    // Open remote directory
    dir = sftp_opendir(sftp, remote_dir);
    if (dir == NULL) {
        fprintf(stderr, "Error opening remote directory: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    // Process each entry in the directory
    while ((attributes = sftp_readdir(sftp, dir)) != NULL) {
        // Skip "." and ".." entries
        if (strcmp(attributes->name, ".") == 0 || strcmp(attributes->name, "..") == 0) {
            sftp_attributes_free(attributes);
            continue;
        }

        // Build full paths
        char remote_path[1024];
        char local_path[1024];
        snprintf(remote_path, sizeof(remote_path), "%s/%s", remote_dir, attributes->name);
        snprintf(local_path, sizeof(local_path), "%s/%s", local_dir, attributes->name);

        // Handle directories or files
        if (attributes->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            rc = download_directory(session, remote_path, local_path);
            if (rc != 0) {
                sftp_attributes_free(attributes);
                sftp_closedir(dir);
                sftp_free(sftp);
                return rc;
            }
        } else if (attributes->type == SSH_FILEXFER_TYPE_REGULAR) {
            rc = download_file(session, remote_path, local_path);
            if (rc != 0) {
                sftp_attributes_free(attributes);
                sftp_closedir(dir);
                sftp_free(sftp);
                return rc;
            }
            printf("Downloaded: %s\n", remote_path);
        }
        sftp_attributes_free(attributes);
    }

    sftp_closedir(dir);
    sftp_free(sftp);
    return 0;
}

int main(int argc, char *argv[]) {
    ssh_session my_ssh_session;
    int rc;
    int verbosity = SSH_LOG_NOLOG;
    char *server_host;
    int server_port = 22;  // Default port
    char *port_pos;
    char *identity_file = NULL;
    char *username = NULL;

    if (argc < 5 || argc > 7) {
        fprintf(stderr, "Usage: %s <upload|download> <local_path> <remote_path> <server[:port]> [identity_file] [username]\n", argv[0]);
        fprintf(stderr, "Example: %s upload ./local_folder /home/user/remote_folder 192.168.1.100:23\n", argv[0]);
        fprintf(stderr, "Example with identity: %s upload ./local_folder /home/user/remote_folder 192.168.1.100:23 ~/.ssh/id_ed25519 chienpham\n", argv[0]);
        return -1;
    }

    // Check for identity file
    if (argc >= 6) {
        identity_file = argv[5];
    }
    
    // Check for username
    if (argc >= 7) {
        username = argv[6];
    } else {
        // Default to current user
        username = getenv("USER");
        if (username == NULL) {
            username = "chienpham";  // Fallback default
        }
    }

    // Parse server[:port] format
    server_host = strdup(argv[4]);
    if (server_host == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        return -1;
    }
    
    // Check if a port is specified using format host:port
    port_pos = strchr(server_host, ':');
    if (port_pos != NULL) {
        *port_pos = '\0';  // Split the string
        server_port = atoi(port_pos + 1);
        if (server_port <= 0) {
            fprintf(stderr, "Invalid port number\n");
            free(server_host);
            return -1;
        }
    }
    
    // Validate that hostname is not empty
    if (server_host[0] == '\0') {
        fprintf(stderr, "Error: Empty hostname. Please provide a valid hostname or IP address.\n");
        free(server_host);
        return -1;
    }

    // Initialize SSH session
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        free(server_host);
        return -1;
    }

    // Lower the verbosity for production use
    verbosity = SSH_LOG_WARNING;
    
    // Set connection options with explicit algorithm selection
    // Include both modern and legacy algorithms for compatibility
    const char *pubkey_algos = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    const char *hostkey_algos = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    
    // Set timeout options to prevent quick disconnections
    int timeout = 30; // 30 seconds
    ssh_options_set(my_ssh_session, SSH_OPTIONS_TIMEOUT, &timeout);
    
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, server_host);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &server_port);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, username);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, pubkey_algos);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOSTKEYS, hostkey_algos);

    // Set identity file if provided
    if (identity_file != NULL) {
        printf("Using identity file: %s\n", identity_file);
        ssh_options_set(my_ssh_session, SSH_OPTIONS_IDENTITY, identity_file);
    }

    printf("Connecting as user: %s\n", username);
    printf("Connecting to %s on port %d...\n", server_host, server_port);
    
    // Try to connect multiple times
    for (int attempt = 1; attempt <= 3; attempt++) {
        rc = ssh_connect(my_ssh_session);
        if (rc == SSH_OK) break;
        
        fprintf(stderr, "Connection attempt %d failed: %s\n", 
                attempt, ssh_get_error(my_ssh_session));
        
        if (attempt < 3) {
            printf("Retrying in 2 seconds...\n");
            sleep(2);
        }
    }
    
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        free(server_host);
        return -1;
    }
    printf("Connection established!\n");

    // Authenticate with public key - with more robust authentication method
    printf("Authenticating with public key...\n");
    
    // Try multiple authentication methods
    rc = SSH_AUTH_DENIED;
    
    // First try none auth to get available methods
    rc = ssh_userauth_none(my_ssh_session, NULL);
    
    // Then try provided identity if any
    if (rc != SSH_AUTH_SUCCESS && identity_file != NULL) {
        ssh_key privkey = NULL;
        if (ssh_pki_import_privkey_file(identity_file, NULL, NULL, NULL, &privkey) == SSH_OK) {
            printf("Trying authentication with specified identity file\n");
            rc = ssh_userauth_publickey(my_ssh_session, NULL, privkey);
            ssh_key_free(privkey);
        }
    }
    
    // If still not successful, try auto method
    if (rc != SSH_AUTH_SUCCESS) {
        printf("Trying automatic public key authentication\n");
        rc = ssh_userauth_publickey_auto(my_ssh_session, NULL, NULL);
    }
    
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with public key: %s\n", ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        free(server_host);
        return -1;
    }
    printf("Authentication successful!\n");

    // Perform file or directory transfer
    if (strcmp(argv[1], "upload") == 0) {
        if (is_directory(argv[2])) {
            printf("Uploading directory %s to %s...\n", argv[2], argv[3]);
            
            // Ensure the remote base directory exists
            create_remote_directory_custom(my_ssh_session, argv[3]);
            
            // Use a simpler upload_directory function
            rc = upload_directory(my_ssh_session, argv[2], argv[3]);
        } else {
            // Create destination directory if needed
            char *last_slash = strrchr(argv[3], '/');
            if (last_slash) {
                char dir_path[1024] = {0};
                size_t path_len = last_slash - argv[3];
                strncpy(dir_path, argv[3], path_len);
                
                printf("Ensuring remote directory exists: %s\n", dir_path);
                create_remote_directory_custom(my_ssh_session, dir_path);
            }
            
            rc = upload_file(my_ssh_session, argv[2], argv[3]);
        }
    } else if (strcmp(argv[1], "download") == 0) {
        sftp_session temp_sftp = sftp_new(my_ssh_session);
        if (temp_sftp == NULL) {
            fprintf(stderr, "Error creating SFTP session\n");
            ssh_disconnect(my_ssh_session);
            ssh_free(my_ssh_session);
            return -1;
        }
        
        if (sftp_init(temp_sftp) != SSH_OK) {
            fprintf(stderr, "Error initializing SFTP session\n");
            sftp_free(temp_sftp);
            ssh_disconnect(my_ssh_session);
            ssh_free(my_ssh_session);
            return -1;
        }
        
        sftp_attributes attrs = sftp_stat(temp_sftp, argv[3]);
        if (attrs != NULL) {
            int is_dir = (attrs->type == SSH_FILEXFER_TYPE_DIRECTORY);
            sftp_attributes_free(attrs);
            sftp_free(temp_sftp);
            
            if (is_dir) {
                printf("Downloading directory %s to %s...\n", argv[3], argv[2]);
                rc = download_directory(my_ssh_session, argv[3], argv[2]);
            } else {
                printf("Downloading file %s to %s...\n", argv[3], argv[2]);
                rc = download_file(my_ssh_session, argv[3], argv[2]);
            }
        } else {
            fprintf(stderr, "Error accessing remote path: %s\n", argv[3]);
            sftp_free(temp_sftp);
            rc = -1;
        }
    } else {
        fprintf(stderr, "Invalid operation. Use 'upload' or 'download'\n");
        rc = -1;
    }

    if (rc == 0) {
        printf("Transfer completed successfully at %s!\n", get_time_str());
    }

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    free(server_host);
    return rc;
}