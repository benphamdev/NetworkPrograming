import socket

print('Creating socket...')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')
print("Connecting with remote host")

target_host = "www.google.com"
target_port = 80

s.connect((target_host, target_port))
print('Connection established')

request = f"GET / HTTP/1.1\r\nHost:{target_host}\r\n\r\n"
s.send(request.encode())

data = s.recv(4096)
print("Data:", str(data))
print("Length:", len(data))
print('Closing the socket')
s.close()