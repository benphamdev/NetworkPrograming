#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>  // for size_t

// Message type definitions
#define MSG_TYPE_DNS "DNS_REQUEST"
#define MSG_TYPE_HTTP "VICTIM_HTTP"

// Configuration constants
#define BUFFER_SIZE 4096
#define PORT 9090
#define INTERFACE "eth0"
#define LOCAL_SERVER_HOST "172.20.0.104"
#define LOCAL_SERVER_PORT 9090
#define VICTIM_IP "172.20.0.102"
#define DNS_PORT 53
#define HTTP_PORT 80
#define MAX_HTML_SIZE 4096
#define INDEX_HTML_PATH "./index.html"
#define SIZE_ETHERNET 14
#define MAX_ETHER 1518

// Common structures
struct tcp_conn_state {
    uint32_t seq;
    uint32_t ack;
    uint16_t sport;
    uint16_t dport;
    uint16_t window;
    uint8_t flags;
};

// Forward declarations
struct conn_info {
    uint32_t seq;
    uint32_t ack;
    uint16_t sport;
    uint16_t dport;
    uint16_t window;
    uint8_t flags;
};

struct dns_info {
    uint16_t txid;
    char query[256];
    uint16_t src_port;
};

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Function prototypes
void send_dns_response(struct dns_info *dns);
void send_fake_response(const char *response, const char *victim_ip, struct conn_info *conn);
uint16_t chksum(const unsigned short *buf, size_t buflen);
uint16_t calculate_checksum(const unsigned short *buf, size_t buflen);

#endif /* COMMON_H */
