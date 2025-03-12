"""
Socket Reverse Lookup Example
This script performs a reverse DNS lookup for a given IP address.
"""
import socket

def reverse_dns_lookup(ip_address):
    """
    Perform a reverse DNS lookup for the given IP address.
    
    Args:
        ip_address (str): The IP address to look up
        
    Returns:
        None: Prints the results directly
    """
    try:
        result = socket.gethostbyaddr(ip_address)
        print("The host name is:", result[0])
        print("IP addresses:")
        for item in result[2]:
            print(" " + item)
    except socket.error as e:
        print("Error resolving IP address:", e)

if __name__ == "__main__":
    # Example IP address (Google DNS)
    ip_to_lookup = "8.8.8.8"
    reverse_dns_lookup(ip_to_lookup)