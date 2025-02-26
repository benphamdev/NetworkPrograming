#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#define BUFFER_SIZE 256

int main() {
    ssh_session my_ssh_session;
    ssh_channel channel;
    int rc;
    char buffer[BUFFER_SIZE];
    struct pollfd fds[2];
    
    // Initialize SSH session
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        exit(-1);
    }

    // Set connection options
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "192.168.255.151");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "chienpham");
    
    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Authenticate
    rc = ssh_userauth_password(my_ssh_session, NULL, "1234");
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating: %s\n", ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Create a new channel
    channel = ssh_channel_new(my_ssh_session);
    if (channel == NULL) {
        fprintf(stderr, "Error creating channel\n");
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
    
    // Open session
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error opening session: %s\n", ssh_get_error(my_ssh_session));
        goto cleanup;
    }

    // Request PTY
    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error requesting PTY: %s\n", ssh_get_error(my_ssh_session));
        goto cleanup;
    }

    // Request shell
    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(my_ssh_session));
        goto cleanup;
    }

    // Set up non-blocking I/O
    ssh_channel_set_blocking(channel, 0);

    // Set up poll for stdin and channel
    fds[0].fd = 0;        // stdin
    fds[0].events = POLLIN;
    fds[1].fd = ssh_get_fd(my_ssh_session);
    fds[1].events = POLLIN;

    printf("Interactive shell started. Type 'exit' to quit.\n");

    // Main loop for shell interaction
    while (1) {
        rc = poll(fds, 2, -1);
        if (rc < 0) {
            fprintf(stderr, "Error in poll\n");
            break;
        }

        // Check for input from stdin
        if (fds[0].revents & POLLIN) {
            int nbytes = read(0, buffer, sizeof(buffer));
            if (nbytes <= 0) {
                break;
            }
            ssh_channel_write(channel, buffer, nbytes);
            
            // Check for exit command
            if (strncmp(buffer, "exit\n", 5) == 0) {
                break;
            }
        }

        // Check for data from server
        if (fds[1].revents & POLLIN) {
            int nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
            if (nbytes < 0) {
                break;
            }
            if (nbytes > 0) {
                write(1, buffer, nbytes);
            }
        }

        // Check if channel is closed
        if (ssh_channel_is_closed(channel)) {
            break;
        }
    }

cleanup:
    // Cleanup
    if (channel) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    return 0;
}
