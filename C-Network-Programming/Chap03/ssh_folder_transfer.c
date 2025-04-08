#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

#define BUFFER_SIZE 4096

// Function to create directory on the remote server
int create_remote_directory(ssh_session session, sftp_session sftp, const char *dir_path) {
    int rc = sftp_mkdir(sftp, dir_path, 0755);
    if (rc != SSH_OK) {
        if (sftp_get_error(sftp) == SSH_FX_FILE_ALREADY_EXISTS) {
            return SSH_OK; // Directory already exists
        }
        fprintf(stderr, "Error creating remote directory %s: %s\n", 
                dir_path, ssh_get_error(session));
        return rc;
    }
    return SSH_OK;
}

// Function to ensure a local directory exists
int create_local_directory(const char *dir_path) {
    struct stat st = {0};
    if (stat(dir_path, &st) == -1) {
        if (mkdir(dir_path, 0755) == -1) {
            fprintf(stderr, "Error creating local directory %s: %s\n", 
                    dir_path, strerror(errno));
            return -1;
        }
    }
    return 0;
}

// Function to upload a single file
int upload_file(ssh_session session, sftp_session sftp, const char *local_path, const char *remote_path) {
    FILE *local_file;
    sftp_file remote_file;
    char buffer[BUFFER_SIZE];
    size_t nread, nwritten;
    
    local_file = fopen(local_path, "rb");
    if (local_file == NULL) {
        fprintf(stderr, "Error opening local file %s: %s\n", local_path, strerror(errno));
        return -1;
    }
    
    remote_file = sftp_open(sftp, remote_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (remote_file == NULL) {
        fprintf(stderr, "Error opening remote file %s: %s\n", 
                remote_path, ssh_get_error(session));
        fclose(local_file);
        return -1;
    }
    
    while ((nread = fread(buffer, 1, BUFFER_SIZE, local_file)) > 0) {
        nwritten = sftp_write(remote_file, buffer, nread);
        if (nwritten != nread) {
            fprintf(stderr, "Error writing to remote file: %s\n", 
                    ssh_get_error(session));
            sftp_close(remote_file);
            fclose(local_file);
            return -1;
        }
    }
    
    sftp_close(remote_file);
    fclose(local_file);
    printf("Uploaded: %s -> %s\n", local_path, remote_path);
    return 0;
}

// Function to download a single file
int download_file(ssh_session session, sftp_session sftp, const char *remote_path, const char *local_path) {
    sftp_file remote_file;
    FILE *local_file;
    char buffer[BUFFER_SIZE];
    ssize_t nread;
    
    remote_file = sftp_open(sftp, remote_path, O_RDONLY, 0);
    if (remote_file == NULL) {
        fprintf(stderr, "Error opening remote file %s: %s\n", 
                remote_path, ssh_get_error(session));
        return -1;
    }
    
    local_file = fopen(local_path, "wb");
    if (local_file == NULL) {
        fprintf(stderr, "Error opening local file %s: %s\n", local_path, strerror(errno));
        sftp_close(remote_file);
        return -1;
    }
    
    while ((nread = sftp_read(remote_file, buffer, BUFFER_SIZE)) > 0) {
        if (fwrite(buffer, 1, nread, local_file) != nread) {
            fprintf(stderr, "Error writing to local file: %s\n", strerror(errno));
            sftp_close(remote_file);
            fclose(local_file);
            return -1;
        }
    }
    
    sftp_close(remote_file);
    fclose(local_file);
    printf("Downloaded: %s -> %s\n", remote_path, local_path);
    return 0;
}

// Function to recursively upload a folder
int upload_folder(ssh_session session, sftp_session sftp, const char *local_folder, const char *remote_folder) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char local_path[1024];
    char remote_path[1024];
    
    // Create remote directory if it doesn't exist
    if (create_remote_directory(session, sftp, remote_folder) != SSH_OK) {
        return -1;
    }
    
    // Open local directory
    dir = opendir(local_folder);
    if (dir == NULL) {
        fprintf(stderr, "Error opening local directory %s: %s\n", local_folder, strerror(errno));
        return -1;
    }
    
    // Iterate through directory entries
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Construct full paths
        snprintf(local_path, sizeof(local_path), "%s/%s", local_folder, entry->d_name);
        snprintf(remote_path, sizeof(remote_path), "%s/%s", remote_folder, entry->d_name);
        
        // Get file stats
        if (stat(local_path, &statbuf) < 0) {
            fprintf(stderr, "Error getting file stats for %s: %s\n", local_path, strerror(errno));
            continue;
        }
        
        if (S_ISDIR(statbuf.st_mode)) {
            // Recursively upload subdirectory
            if (upload_folder(session, sftp, local_path, remote_path) < 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(statbuf.st_mode)) {
            // Upload file
            if (upload_file(session, sftp, local_path, remote_path) < 0) {
                closedir(dir);
                return -1;
            }
        }
    }
    
    closedir(dir);
    return 0;
}

// Function to recursively download a folder
int download_folder(ssh_session session, sftp_session sftp, const char *remote_folder, const char *local_folder) {
    sftp_dir dir;
    sftp_attributes attributes;
    char local_path[1024];
    char remote_path[1024];
    
    // Create local directory if it doesn't exist
    if (create_local_directory(local_folder) < 0) {
        return -1;
    }
    
    // Open remote directory
    dir = sftp_opendir(sftp, remote_folder);
    if (dir == NULL) {
        fprintf(stderr, "Error opening remote directory %s: %s\n", 
                remote_folder, ssh_get_error(session));
        return -1;
    }
    
    // Iterate through directory entries
    while ((attributes = sftp_readdir(sftp, dir)) != NULL) {
        // Skip . and ..
        if (strcmp(attributes->name, ".") == 0 || strcmp(attributes->name, "..") == 0) {
            sftp_attributes_free(attributes);
            continue;
        }
        
        // Construct full paths
        snprintf(remote_path, sizeof(remote_path), "%s/%s", remote_folder, attributes->name);
        snprintf(local_path, sizeof(local_path), "%s/%s", local_folder, attributes->name);
        
        if (attributes->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            // Recursively download subdirectory
            if (download_folder(session, sftp, remote_path, local_path) < 0) {
                sftp_attributes_free(attributes);
                sftp_closedir(dir);
                return -1;
            }
        } else if (attributes->type == SSH_FILEXFER_TYPE_REGULAR) {
            // Download file
            if (download_file(session, sftp, remote_path, local_path) < 0) {
                sftp_attributes_free(attributes);
                sftp_closedir(dir);
                return -1;
            }
        }
        
        sftp_attributes_free(attributes);
    }
    
    sftp_closedir(dir);
    return 0;
}

int main(int argc, char *argv[]) {
    ssh_session session;
    sftp_session sftp;
    int rc;
    
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <upload|download> <local_folder> <remote_folder>\n", argv[0]);
        return -1;
    }
    
    // Initialize SSH session
    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        return -1;
    }
    
    // Set connection options
    ssh_options_set(session, SSH_OPTIONS_HOST, "192.168.255.151"); // Modify this IP
    ssh_options_set(session, SSH_OPTIONS_USER, "chienpham"); // Modify this user
    
    // Set specific private key path
    const char *home = getenv("HOME");
    char private_key_path[1024];
    snprintf(private_key_path, sizeof(private_key_path), "%s/.ssh/id_rsa_key", home);
    
    // Check if the key exists
    if (access(private_key_path, F_OK) == -1) {
        fprintf(stderr, "SSH key not found at %s\n", private_key_path);
        fprintf(stderr, "Run ssh_client_key first to generate keys\n");
        ssh_free(session);
        return -1;
    }
    
    // Set the SSH identity (private key)
    ssh_options_set(session, SSH_OPTIONS_IDENTITY, private_key_path);
    
    // Connect to server
    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting: %s\n", ssh_get_error(session));
        ssh_free(session);
        return -1;
    }
    
    // Try public key authentication
    rc = ssh_userauth_publickey_auto(session, NULL, NULL);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }
    
    printf("Successfully authenticated using SSH key\n");
    
    // Initialize SFTP session
    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error creating SFTP session: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }
    
    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }
    
    // Perform folder transfer
    if (strcmp(argv[1], "upload") == 0) {
        printf("Uploading folder %s to %s...\n", argv[2], argv[3]);
        rc = upload_folder(session, sftp, argv[2], argv[3]);
    } else if (strcmp(argv[1], "download") == 0) {
        printf("Downloading folder %s to %s...\n", argv[3], argv[2]);
        rc = download_folder(session, sftp, argv[3], argv[2]);
    } else {
        fprintf(stderr, "Invalid operation. Use 'upload' or 'download'\n");
        rc = -1;
    }
    
    if (rc == 0) {
        printf("Folder transfer completed successfully!\n");
    } else {
        fprintf(stderr, "Folder transfer failed with error code %d\n", rc);
    }
    
    // Cleanup
    sftp_free(sftp);
    ssh_disconnect(session);
    ssh_free(session);
    
    return rc;
}
