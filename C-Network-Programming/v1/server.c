#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#define PORT "2222"
#define RSA_KEY "./host_rsa_key"

int main() {
    ssh_bind sshbind;
    ssh_session session;
    ssh_event event;
    int rc;

    // Initialize SSH
    ssh_init();

    // Create SSH bind
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        printf("Error: Failed to create SSH bind\n");
        return 1;
    }

    // Set SSH bind options
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, RSA_KEY);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, PORT);

    // Start listening
    printf("Server starting on port %s...\n", PORT);
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error: Cannot bind to port: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        return 1;
    }
    printf("Server listening on port %s\n", PORT);

    while (1) {
        // Create a new session for each connection
        session = ssh_new();
        if (session == NULL) {
            printf("Error: Failed to create session\n");
            continue;
        }

        // Accept incoming connection
        rc = ssh_bind_accept(sshbind, session);
        if (rc == SSH_ERROR) {
            printf("Error: Accept failed: %s\n", ssh_get_error(sshbind));
            ssh_free(session);
            continue;
        }
        printf("Connection accepted\n");

        // Handle key exchange
        if (ssh_handle_key_exchange(session) != SSH_OK) {
            printf("Error: Key exchange failed: %s\n", ssh_get_error(session));
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        printf("Key exchange completed\n");

        // Create event loop for the session
        event = ssh_event_new();
        if (event == NULL) {
            printf("Error creating event: %s\n", ssh_get_error(session));
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        if (ssh_event_add_session(event, session) != SSH_OK) {
            printf("Error adding session to event: %s\n", ssh_get_error(session));
            ssh_event_free(event);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        // Handle service request (ssh-userauth)
        int service_accepted = 0;
        while (!service_accepted) {
            if (ssh_event_dopoll(event, 1000) == SSH_ERROR) {
                printf("Error in event loop: %s\n", ssh_get_error(session));
                ssh_event_free(event);
                ssh_disconnect(session);
                ssh_free(session);
                return 1;
            }
            ssh_message message = ssh_message_get(session);
            if (message) {
                if (ssh_message_type(message) == SSH_REQUEST_SERVICE) {
                    if (strcmp(ssh_message_service_service(message), "ssh-userauth") == 0) {
                        ssh_message_service_reply_success(message);
                        printf("Service request ssh-userauth accepted\n");
                        service_accepted = 1;
                    } else {
                        ssh_message_reply_default(message);
                    }
                } else {
                    ssh_message_reply_default(message);
                }
                ssh_message_free(message);
            }
        }

        // Handle authentication
        int authenticated = 0;
        int auth_attempts = 0;
        int max_attempts = 20; // Limit authentication attempts

        while (!authenticated && auth_attempts < max_attempts) {
            if (ssh_event_dopoll(event, 1000) == SSH_ERROR) {
                printf("Error in event loop: %s\n", ssh_get_error(session));
                break;
            }
            ssh_message message = ssh_message_get(session);
            if (message) {
                if (ssh_message_type(message) == SSH_REQUEST_AUTH) {
                    switch (ssh_message_subtype(message)) {
                        case SSH_AUTH_METHOD_PASSWORD:
                            printf("Processing password authentication request...\n");
                            // Accept all passwords (for simplicity)
                            ssh_message_auth_reply_success(message, 0);
                            authenticated = 1;
                            break;
                        case SSH_AUTH_METHOD_PUBLICKEY:
                            printf("Processing public key authentication request...\n");
                            // Accept all public keys (for simplicity)
                            ssh_message_auth_reply_success(message, 0);
                            authenticated = 1;
                            break;
                        case SSH_AUTH_METHOD_NONE:
                            printf("No authentication method specified...\n");
                            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
                            ssh_message_reply_default(message);
                            break;
                        default:
                            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
                            ssh_message_reply_default(message);
                    }
                } else {
                    ssh_message_reply_default(message);
                }
                ssh_message_free(message);
            }
            auth_attempts++;
        }

        if (!authenticated) {
            printf("Authentication timeout or failed\n");
            ssh_event_remove_session(event, session);
            ssh_event_free(event);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        printf("Client authenticated successfully\n");

        // Handle channels and SFTP requests
        ssh_channel channel = NULL;
        do {
            ssh_message message = ssh_message_get(session);
            if (message) {
                if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
                    ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
                    channel = ssh_message_channel_request_open_reply_accept(message);
                    ssh_message_free(message);
                    break;
                } else {
                    ssh_message_reply_default(message);
                    ssh_message_free(message);
                }
            } else {
                break;
            }
        } while (ssh_is_connected(session));

        if (channel) {
            printf("Channel opened for SFTP\n");
            // Handle channel requests (e.g., SFTP subsystem)
            do {
                ssh_message message = ssh_message_get(session);
                if (message) {
                    if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
                        if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SUBSYSTEM &&
                            strcmp(ssh_message_channel_request_subsystem(message), "sftp") == 0) {
                            printf("SFTP subsystem requested\n");
                            ssh_message_channel_request_reply_success(message);
                        } else {
                            ssh_message_reply_default(message);
                        }
                    } else {
                        ssh_message_reply_default(message);
                    }
                    ssh_message_free(message);
                }

                // Check for channel EOF
                if (ssh_channel_is_eof(channel)) {
                    break;
                }

                ssh_event_dopoll(event, 1000);
            } while (ssh_is_connected(session));

            ssh_channel_close(channel);
            ssh_channel_free(channel);
        }

        // Clean up session
        ssh_event_remove_session(event, session);
        ssh_event_free(event);
        ssh_disconnect(session);
        ssh_free(session);
    }

    // Clean up SSH bind and finalize
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}