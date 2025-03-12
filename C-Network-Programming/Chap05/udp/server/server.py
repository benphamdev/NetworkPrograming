import socket
import sys

SERVER_IP = "127.0.0.1"
SERVER_PORT = 6789

socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket_server.bind((SERVER_IP, SERVER_PORT))
print(f"[*] Server UDP Listening on {SERVER_IP}:{SERVER_PORT}")

try:
    while True:
        data, address = socket_server.recvfrom(4096)
        socket_server.sendto("I am the server accepting connections...".encode(), address)

        data = data.strip()
        print(f"Message {data.decode()} received from {address}")

        try:
            response = f"Hi {sys.platform}"
        except Exception as e:
            response = f"{sys.exc_info()[0]}"
        print(f"Response: {response}")
        socket_server.sendto(response.encode('utf-8'), address)
except KeyboardInterrupt:
    print("\nShutting down server...")
    print("Press Ctrl+C again to force quit")
    try:
        socket_server.close()
        print("Server socket closed successfully")
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nForce quitting...")
        sys.exit(1)
finally:
    socket_server.close()