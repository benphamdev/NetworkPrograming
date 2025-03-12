import socket
import sys

host = "127.0.0.1"
port = 9998

try:
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mysocket.connect((host, port))
    print(f'Connected to host {host} in port: {port}')
    
    message = mysocket.recv(1024)
    print(f"Message received from the server: {message.decode('utf-8')}")
    
    print("Enter 'quit' to exit this client")
    print("Enter 'exit' to shut down the server and exit")
    
    while True:
        try:
            message = input("Enter your message > ")
            
            # Check for exit commands
            if message.lower() == "quit":
                print("Closing the connection...")
                break
                
            # Send the message
            mysocket.send(message.encode('utf-8'))
            
            # If we sent exit command, wait for server response before quitting
            if message.lower() == "exit":
                try:
                    # Set a timeout to avoid hanging
                    mysocket.settimeout(3)
                    response = mysocket.recv(1024).decode('utf-8')
                    print(f"Server response: {response}")
                except socket.timeout:
                    pass
                print("Server shutdown initiated. Exiting...")
                break
                
            # Get response from server
            try:
                mysocket.settimeout(3)  # Set timeout for receiving
                response = mysocket.recv(1024).decode('utf-8')
                print(f"Server response: {response}")
            except socket.timeout:
                print("No response from server. It may be busy or disconnected.")
                
        except KeyboardInterrupt:
            print("\nExiting client due to user interrupt...")
            break
            
except socket.error as error:
    print(f"Socket error: {error}")
except Exception as e:
    print(f"Unexpected error: {e}")
finally:
    try:
        mysocket.close()
        print("Connection closed.")
    except:
        pass
    sys.exit(0)