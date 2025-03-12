import argparse
from socket import AF_INET, SOCK_STREAM, socket, gethostbyname
from threading import Thread
from typing import List, Optional


def socket_scan(host: str, port: int) -> None:
    """Scan a single port on the specified host."""
    try:
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f'[+] {port}/tcp open')
            else:
                print(f'[-] {port}/tcp closed')
    except Exception as exception:
        print(f'[-] {port}/tcp closed')
        print(f'[-] Reason: {exception}')


def port_scanning(host: str, ports: List[int]) -> None:
    """Scan multiple ports on the specified host using threads."""
    try:
        ip = gethostbyname(host)
        print(f'[+] Scan Results for: {ip}')
    except Exception:
        print(f"[-] Cannot resolve '{host}': Unknown host")
        return

    threads = []
    for port in ports:
        t = Thread(target=socket_scan, args=(ip, port))
        threads.append(t)
        t.start()
    
    # Wait for all threads to complete (optional)
    for t in threads:
        t.join()


def main() -> None:
    """Parse command line arguments and initiate port scanning."""
    parser = argparse.ArgumentParser(description='Port Scanner Tool')
    parser.add_argument('-H', '--host', type=str, required=True, help='specify target host')
    parser.add_argument('-P', '--ports', type=str, required=True, 
                       help='specify port(s) separated by comma')
    
    args = parser.parse_args()
    
    try:
        ports = [int(port) for port in args.ports.split(',')]
        port_scanning(args.host, ports)
    except ValueError:
        print("[-] Error: Ports must be integers")


if __name__ == '__main__':
    main()