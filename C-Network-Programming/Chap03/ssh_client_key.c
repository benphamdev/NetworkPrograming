#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int setup_ssh_keys(const char *private_key_path) {
    char cmd[2048];
    char ssh_dir[1024];
    const char *home = getenv("HOME");
    
    // Create .ssh directory
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    mkdir(ssh_dir, 0700);
    
    // Generate key pair with specific name
    snprintf(cmd, sizeof(cmd),
        "ssh-keygen -t rsa -b 4096 -f %s -N '' -q", private_key_path);
    
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to generate SSH key pair\n");
        return -1;
    }

    // Set correct permissions
    snprintf(cmd, sizeof(cmd), "chmod 600 %s", private_key_path);
    system(cmd);
    
    snprintf(cmd, sizeof(cmd), "chmod 644 %s.pub", private_key_path);
    system(cmd);

    printf("Generated key pair:\n");
    printf("Private key: %s\n", private_key_path);
    printf("Public key: %s.pub\n", private_key_path);
    
    return 0;
}

int main() {
    ssh_session my_ssh_session;
    int rc;
    ssh_channel channel;
    char buffer[256];
    int nbytes;
    
    // Set up specific key paths
    const char *home = getenv("HOME");
    char private_key_path[1024];
    snprintf(private_key_path, sizeof(private_key_path), "%s/.ssh/id_rsa_key", home);

    // Check if key exists, generate if it doesn't
    if (access(private_key_path, F_OK) == -1) {
        printf("No SSH key found. Generating new key pair...\n");
        if (setup_ssh_keys(private_key_path) != 0) {
            exit(-1);
        }
        printf("\nIMPORTANT: Before continuing, please copy the public key to the server:\n");
        printf("On the server, run:\n");
        printf("mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys\n");
        printf("Then paste the contents of this file:\n");
        printf("cat %s.pub\n", private_key_path);
        printf("\nAfter copying the key, press Enter to continue...");
        getchar();
    }

    // Initialize SSH session
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        exit(-1);
    }

    // Set connection options
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "192.168.255.151");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &(int){22});
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "chienpham");
    
    // Set the specific private key path
    ssh_options_set(my_ssh_session, SSH_OPTIONS_IDENTITY, private_key_path);
    
    // Set key type explicitly
    const char *key_types = "ssh-rsa,rsa-sha2-512,rsa-sha2-256";
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, key_types);
    
    // Enable verbose mode for debugging
    int verbosity = SSH_LOG_PROTOCOL;
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Skip known hosts verification temporarily for debugging
    ssh_options_set(my_ssh_session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &(int){0});

    // Try authentication with NULL password
    rc = ssh_userauth_publickey_auto(my_ssh_session, NULL, NULL);
    if (rc != SSH_AUTH_SUCCESS) {
        printf("Key authentication failed, trying password authentication...\n");
        
        // Get password from user
        char password[128];
        printf("Enter password for %s: ", "chienpham");
        // Disable echo
        system("stty -echo");
        fgets(password, sizeof(password), stdin);
        // Enable echo
        system("stty echo");
        printf("\n");
        
        // Remove newline from password
        password[strcspn(password, "\n")] = 0;
        
        // Try password authentication
        rc = ssh_userauth_password(my_ssh_session, NULL, password);
        if (rc != SSH_AUTH_SUCCESS) {
            fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(my_ssh_session));
            ssh_disconnect(my_ssh_session);
            ssh_free(my_ssh_session);
            exit(-1);
        }
        printf("Successfully authenticated using password!\n");
    } else {
        printf("Successfully authenticated using SSH key!\n");
    }

    // Create a new channel
    channel = ssh_channel_new(my_ssh_session);
    if (channel == NULL) {
        fprintf(stderr, "Error creating channel\n");
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
    
    // Open a session
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error opening channel: %s\n", ssh_get_error(my_ssh_session));
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Request a pseudo-terminal
    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error requesting PTY: %s\n", ssh_get_error(my_ssh_session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Request shell
    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(my_ssh_session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    printf("Interactive shell started. Type commands or 'exit' to quit.\n");

    // Cleanup
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    return 0;
}
