#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 8080

int main(int argc, char const* argv[]) {
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    char message[1024];

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "172.20.0.100", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    while (1) {
        printf("Enter message: ");
        fflush(stdout); // Ensure the prompt is displayed immediately
        fgets(message, 1024, stdin);
        message[strcspn(message, "\n")] = 0; // Remove newline character

        send(sock, message, strlen(message), 0);
        printf("Message sent\n");

        valread = read(sock, buffer, 1024);
        printf("Response from server: %s\n", buffer);
    }

    // closing the connected socket
    close(sock);
    return 0;
}