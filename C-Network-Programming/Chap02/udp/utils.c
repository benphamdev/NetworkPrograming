#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "utils.h"

void debug_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("[DEBUG %s] ", timestamp);
    vprintf(format, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

// Update function implementation to match declaration
uint16_t calculate_checksum(const unsigned short *buf, size_t buflen) {
    uint32_t sum = 0;
    size_t i;

    // Sum up 16-bit words
    for (i = 0; i < buflen/2; i++) {
        sum += buf[i];
    }

    // Handle odd byte if present
    if (buflen & 1) {
        sum += ((unsigned char*)buf)[buflen-1];
    }

    // Add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);     // Add high 16 to low 16
    sum += (sum >> 16);                      // Add carry
    return (uint16_t)~sum;                   // Return ones complement
}

// Alias chksum to calculate_checksum for compatibility
uint16_t chksum(const unsigned short *buf, size_t buflen) {
    return calculate_checksum(buf, buflen);
}

char* read_html_file() {
    static char html_content[MAX_HTML_SIZE];
    FILE *fp = fopen(INDEX_HTML_PATH, "r");
    if (!fp) {
        debug_log("Error opening index.html: %s", strerror(errno));
        return NULL;
    }
    size_t bytes_read = fread(html_content, 1, MAX_HTML_SIZE - 1, fp);
    fclose(fp);
    if (bytes_read == 0) return NULL;
    html_content[bytes_read] = '\0';
    return html_content;
}

void print_packet_content(unsigned char *buffer, int size) {
    printf("\n==== Packet Content ====\n");
    for(int i = 0; i < size; i++) {
        if(i % 16 == 0) printf("\n%04X: ", i);
        printf("%02X ", buffer[i]);
        if((i + 1) % 16 == 0) {
            printf("  ");
            for(int j = i - 15; j <= i; j++) {
                printf("%c", (buffer[j] >= 32 && buffer[j] <= 126) ? buffer[j] : '.');
            }
        }
    }
    printf("\n=====================\n");
}

void error(const char *msg) {
    perror(msg);
    exit(1);
}
