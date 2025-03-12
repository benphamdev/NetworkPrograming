import socket
import os
import signal
import threading
import sys
import time

def get_html_content():
    try:
        # Get the directory of the current script
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Path to index.html
        index_path = os.path.join(current_dir, 'index.html')
        
        with open(index_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        print(f"Error reading HTML file: {e}")
        return "<html><body><h1>Error reading page</h1></body></html>"

# Signal handler function
def signal_handler(sig, frame):
    print("\nCtrl+C được nhấn. Đang tắt server...")
    # Exit immediately with status code 0
    os._exit(0)

# Client handler thread function
def handle_client(client_socket, client_address):
    try:
        # Receive client request
        request = client_socket.recv(1024).decode('utf-8')
        print(f'Request from {client_address}:\n{request}')
        
        # Get HTML content
        html_content = get_html_content()
        
        # Create HTTP response
        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html_content)}\r\n"
        response += "\r\n"
        response += html_content
        
        # Send response
        client_socket.sendall(response.encode('utf-8'))
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"Connection with {client_address} closed")

def run_server(host='localhost', port=8080):
    # Set up signal handler for Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow reuse of the address
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Set socket to non-blocking with a timeout
    server_socket.settimeout(0.1)
    
    # Track active client threads
    client_threads = []
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f'Multithreaded server started on http://{host}:{port}')
        print('Press Ctrl+C to stop the server')
        
        while True:
            try:
                # Accept client connection
                client_socket, client_address = server_socket.accept()
                print(f'New connection from: {client_address}')
                
                # Create a new thread to handle the client
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True  # Set as daemon so it terminates when main thread exits
                client_thread.start()
                
                # Store thread reference
                client_threads.append(client_thread)
                
                # Clean up completed threads
                client_threads = [t for t in client_threads if t.is_alive()]
                print(f"Active connections: {len(client_threads)}")
                
            except socket.timeout:
                # Socket timeout, continue the loop
                continue
            except Exception as e:
                if not isinstance(e, KeyboardInterrupt):  # Skip KeyboardInterrupt, handled by signal
                    print(f"Connection error: {e}")
    
    except Exception as e:
        if not isinstance(e, KeyboardInterrupt):  # Skip KeyboardInterrupt, handled by signal
            print(f"Server error: {e}")
    finally:
        # Close server socket
        server_socket.close()
        print("Server socket closed")
        
        # Wait for all client threads to complete (with timeout)
        print("Waiting for active connections to complete...")
        for thread in client_threads:
            thread.join(timeout=1.0)
        
        print("Server shutdown complete")

if __name__ == "__main__":
    # You can specify different host and port by passing arguments
    # run_server('0.0.0.0', 8000)
    run_server()
