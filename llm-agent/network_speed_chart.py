import matplotlib.pyplot as plt
from scapy.all import *

class NetworkTools:
    def __init__(self):
        pass
        
    def get_all_subnets(self):
        # Get the local IP address and subnet
        local_ip = get_if_addr(conf.iface)
        subnet = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
        return [subnet]
        
    def discover_hosts(self, subnet):
        # Use ARP to discover live hosts
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, verbose=False)
        return [rcv.psrc for snd, rcv in ans]
        
    def get_delay_time(self, host):
        # Send ICMP ping and measure round-trip time
        ans, _ = sr(IP(dst=host)/ICMP(), timeout=2, verbose=False)
        if ans:
            return ans[0][1].time - ans[0][0].sent_time
        return float('inf')

def main():
    # Initialize the NetworkTools class
    tools = NetworkTools()

    # Get all subnets
    subnets = tools.get_all_subnets()
    if not subnets:
        print("[!] No subnets found.")
        return

    # Use the first subnet for discovery
    print(f"[*] Using subnet: {subnets[0]}")
    live_hosts = tools.discover_hosts(subnets[0])
    if not live_hosts:
        print("[!] No live hosts found.")
        return

    print(f"[*] Found live hosts: {live_hosts}")

    # Measure delay times
    delay_times = {}
    for host in live_hosts:
        delay = tools.get_delay_time(host)
        delay_times[host] = delay
        print(f"[*] Host: {host}, Delay: {delay:.2f} seconds")

    # Plot the results
    hosts = list(delay_times.keys())
    delays = list(delay_times.values())

    plt.figure(figsize=(10, 6))
    plt.bar(hosts, delays, color='blue')
    plt.xlabel('Hosts')
    plt.ylabel('Delay Time (seconds)')
    plt.title('Network Delay Times from Localhost')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
