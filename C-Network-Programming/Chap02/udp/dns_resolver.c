#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>

#define BUFFER_SIZE 512
#define MAX_ADDRESSES 100
#define INET6_ADDRSTRLEN 46

void error(const char *msg) {
    perror(msg);
    exit(1);
}

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int is_ipv6;
} IP_ADDRESS;

void add_address(IP_ADDRESS addresses[], int *addr_count, const char *ip, int is_ipv6) {
    if (*addr_count >= MAX_ADDRESSES) {
        return;
    }
    for (int i = 0; i < *addr_count; i++) {
        if (strcmp(addresses[i].ip, ip) == 0) {
            return;
        }
    }
    strncpy(addresses[*addr_count].ip, ip, INET6_ADDRSTRLEN - 1);
    addresses[*addr_count].ip[INET6_ADDRSTRLEN - 1] = '\0';
    addresses[*addr_count].is_ipv6 = is_ipv6;
    (*addr_count)++;
}

void get_local_dns_server(char *server_name, char *server_ip) {
    FILE *fp;
    char line[512], *ptr;
    int found = 0;

    fp = fopen("/etc/resolv.conf", "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (line[0] == '#' || line[0] == '\n') continue;
            line[strcspn(line, "\n")] = 0;
            if (strncmp(line, "nameserver", 10) == 0) {
                ptr = line + 10;
                while (*ptr == ' ' || *ptr == '\t') ptr++;
                if (strcmp(ptr, "127.0.0.1") == 0 || 
                    strcmp(ptr, "127.0.0.53") == 0 ||
                    strcmp(ptr, "127.0.0.11") == 0) {
                    continue;
                }
                strncpy(server_ip, ptr, INET6_ADDRSTRLEN - 1);
                server_ip[INET6_ADDRSTRLEN - 1] = '\0';
                found = 1;
                break;
            }
        }
        fclose(fp);
    }

    if (!found) {
        fp = popen("ip route | grep default | awk '{print $3}' 2>/dev/null", "r");
        if (fp != NULL) {
            if (fgets(line, sizeof(line), fp) != NULL) {
                line[strcspn(line, "\n")] = 0;
                strncpy(server_ip, line, INET6_ADDRSTRLEN - 1);
                server_ip[INET6_ADDRSTRLEN - 1] = '\0';
                found = 1;
            }
            pclose(fp);
        }
    }

    if (!found) {
        strcpy(server_ip, "8.8.8.8");
    }

    strcpy(server_name, "UnKnown");
}

int main(int argc, char *argv[]) {
    char *hostname = NULL;
    
    if (argc == 2) {
        if (strchr(argv[1], '.') != NULL) {
            hostname = argv[1];
        }
    } else if (argc == 3) {
        if (strcmp(argv[1], "nslookup") == 0) {
            hostname = argv[2];
        }
    }
    
    if (hostname == NULL) {
        fprintf(stderr, "Usage: %s nslookup <hostname>\n", argv[0]);
        fprintf(stderr, "   or: %s <hostname>\n", argv[0]);
        exit(1);
    }

    char dns_server_name[256];
    char dns_server_ip[INET6_ADDRSTRLEN];
    get_local_dns_server(dns_server_name, dns_server_ip);

    printf("nslookup %s\n", hostname);
    printf("Server:  %s\n", dns_server_name);
    printf("Address:  %s\n\n", dns_server_ip);
    printf("Non-authoritative answer:\n");

    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    IP_ADDRESS addresses[MAX_ADDRESSES];
    int addr_count = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    
    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }
    
    char canonical_name[256] = "";
    if (res->ai_canonname != NULL) {
        strncpy(canonical_name, res->ai_canonname, sizeof(canonical_name) - 1);
        canonical_name[sizeof(canonical_name) - 1] = '\0';
    } else {
        strncpy(canonical_name, hostname, sizeof(canonical_name) - 1);
        canonical_name[sizeof(canonical_name) - 1] = '\0';
    }
    
    printf("Name:    %s\n", canonical_name);
    
    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        int is_ipv6;
        
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            is_ipv6 = 0;
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            is_ipv6 = 1;
        } else {
            continue;
        }
        
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        add_address(addresses, &addr_count, ipstr, is_ipv6);
    }
    
    if (addr_count > 0) {
        printf("Addresses:  ");
        int first = 1;
        for (int i = 0; i < addr_count; i++) {
            if (addresses[i].is_ipv6) {
                if (first) {
                    printf("%s\n", addresses[i].ip);
                    first = 0;
                } else {
                    printf("          %s\n", addresses[i].ip);
                }
            }
        }
        for (int i = 0; i < addr_count; i++) {
            if (!addresses[i].is_ipv6) {
                if (first) {
                    printf("%s\n", addresses[i].ip);
                    first = 0;
                } else {
                    printf("          %s\n", addresses[i].ip);
                }
            }
        }
    } else {
        printf("No addresses found for %s\n", hostname);
    }
    
    if (strcmp(hostname, canonical_name) != 0) {
        printf("Aliases:  %s\n", hostname);
    }
    
    freeaddrinfo(res);
    return 0;
}