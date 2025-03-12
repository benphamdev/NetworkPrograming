import socket
import os
import sys
import signal

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
    # Thoát ngay lập tức với mã 0
    os._exit(0)

def run_server():
    # Thiết lập signal handler cho Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, signal_handler)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow reuse of the address
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Thiết lập socket là non-blocking
    server_socket.settimeout(0.1)
    
    try:
        server_socket.bind(('localhost', 8080))
        server_socket.listen(5)
        print('Server started on http://localhost:8080')
        print('Press Ctrl+C to stop the server')
        
        while True:
            try:
                print('Waiting for connections...')
                client_socket, client_address = server_socket.accept()
                print(f'Connection from: {client_address}')
                
                try:
                    # Receive client request
                    request = client_socket.recv(1024).decode('utf-8')
                    print(f'Request:\n{request}')
                    
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
                    print(f"Error handling request: {e}")
                finally:
                    client_socket.close()
            except socket.timeout:
                # Socket timeout, tiếp tục vòng lặp
                continue
            except Exception as e:
                if not isinstance(e, KeyboardInterrupt):  # Bỏ qua KeyboardInterrupt, đã xử lý bởi signal
                    print(f"Error: {e}")
                
    except Exception as e:
        if not isinstance(e, KeyboardInterrupt):  # Bỏ qua KeyboardInterrupt, đã xử lý bởi signal
            print(f"Server error: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    run_server()