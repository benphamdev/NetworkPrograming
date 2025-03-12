import socket
import threading
import signal
import sys

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9998

# family = Internet, type = stream socket means TCP
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER_IP, SERVER_PORT))
server.listen(5)
print(f"[*] Server Listening on {SERVER_IP}:{SERVER_PORT}")

# Flag to control server running state
running = True

def handle_client(client_socket):
    try:
        request = client_socket.recv(1024)
        msg = request.decode()
        print(f"[*] Received request: {msg} from client {client_socket.getpeername()}")
        
        # Check if client sent an exit command
        if msg.lower() == "exit":
            print(f"[*] Client {client_socket.getpeername()} requested server shutdown")
            client_socket.send(b"Server shutting down...")
            shutdown_server()
        else:
            client_socket.send(b"ACK")
            
    except Exception as e:
        print(f"[!] Error handling client: {e}")
    finally:
        client_socket.close()

def shutdown_server():
    global running
    print("[*] Initiating server shutdown...")
    running = False
    # Create a dummy connection to unblock the accept() call
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
        s.close()
    except:
        pass

def signal_handler(sig, frame):
    print("\n[*] Caught Ctrl+C, shutting down...")
    shutdown_server()

# Register signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

# Make server socket unblocking with a timeout so it can check running flag
server.settimeout(1)

try:
    while running:
        try:
            client, addr = server.accept()
            if not running:
                client.close()
                break
                
            print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")
            client.send("I am the server accepting connections...".encode())
            
            # Create a thread to handle the client
            client_handler = threading.Thread(target=handle_client, args=(client,))
            client_handler.daemon = True  # Set as daemon so it terminates with main thread
            client_handler.start()
        except socket.timeout:
            # This allows the loop to check the running flag periodically
            continue
        except Exception as e:
            if running:  # Only show error if we're still supposed to be running
                print(f"[!] Error accepting connection: {e}")
    
    print("[*] Server shutdown complete.")
except Exception as e:
    print(f"[!] Unexpected error: {e}")
finally:
    server.close()
    sys.exit(0)