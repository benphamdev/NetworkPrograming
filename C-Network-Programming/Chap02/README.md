To set up and run the network programming examples in Chapter 2, follow these steps:

1. Start the Docker containers using Docker Compose:

   ```sh
   docker compose -f ./docker-compose_c2.yaml -p chap2 up -d
   ```

2. Compile the TCP server with multiple threads:

   ```sh
   gcc tcp_server_multiple_thread.c -o tcp_server_multiple_thread.o
   ```

3. Run the compiled TCP server:

   ```sh
   ./tcp_server_multiple_thread.o
   ```

4. Compile the web server:

   ```sh
   gcc web_server.c -o web_server.o
   ```

5. Test the web server using `curl`:

   ```sh
   curl http://172.20.0.100:8081
   ```

6. Set up udp

```sh
gcc udp_client.c -o udp_client.o
```

docker run multiple service

```sh
docker compose -f ./docker-compose_c2.yaml -p chap2 up -d sniffer udp-server cli-client1
```

```sh
docker-compose -f docker-compose_c2.yaml down
```

```sh
docker run --network host --name chap2-udp-client-1 gcc-core
```

```sh
docker network disconnect bridge chap2-udp-client-1
docker network connect host chap2-udp-client-1
```

Note:

# Clear DNS cache

sudo systemd-resolve --flush-caches

# Set DNS server to attacker's IP

sudo sh -c 'echo "nameserver 192.168.255.3" > /etc/resolv.conf'

# Test DNS resolution

nslookup google.com 192.168.255.3

# Try curl with verbose output

curl -v google.com:8081

# TCP vs UDP Server: Similarities and Differences

## Similarities

### 1. Socket API Foundation

Both server types use the socket API and similar address structures:

```c
// Both use sockaddr_in
struct sockaddr_in servaddr;  // UDP
struct sockaddr_in serv_addr; // TCP
```

### 2. Basic Setup Process

Both follow similar initialization steps:

- Create socket
- Configure server address
- Bind to port
- Process client messages in a loop

### 3. Address Configuration

Both use identical address family and IP configuration:

```c
// UDP
servaddr.sin_family = AF_INET;
servaddr.sin_addr.s_addr = INADDR_ANY;
servaddr.sin_port = htons(PORT);

// TCP
serv_addr.sin_family = AF_INET;
serv_addr.sin_addr.s_addr = INADDR_ANY;
serv_addr.sin_port = htons(portno);
```

### 4. Error Handling Approach

Both implement similar error handling:

```c
// Both use error() function
void error(const char *msg) {
    perror(msg);
    exit(1);
}
```

## Differences

### 1. Socket Type

The fundamental difference starts at socket creation:

```c
// TCP: Connection-oriented stream socket
sockfd = socket(AF_INET, SOCK_STREAM, 0);

// UDP: Connectionless datagram socket
sockfd = socket(AF_INET, SOCK_DGRAM, 0);
```

### 2. Connection Management

**TCP**: Requires connection establishment

```c
// Required for TCP only
listen(sockfd, 5);
newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
```

**UDP**: No connection concept, directly exchanges messages

```c
// UDP just receives from any client
recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
         (struct sockaddr *)&clientaddr, &len);
```

### 3. Client Handling

**TCP**: Creates a new socket per client

```c
// A new dedicated socket is created for each client
newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
n = read(newsockfd, buffer, 255);
n = write(newsockfd, "Message received", 16);
```

**UDP**: Uses the same socket for all clients

```c
// Same socket handles all clients
recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
         (struct sockaddr *)&clientaddr, &len);
sendto(sockfd, ack_msg, strlen(ack_msg), 0,
       (const struct sockaddr *)&clientaddr, len);
```

### 4. Client Identification

**TCP**: Client identity preserved throughout connection

```c
// Client is identified by the dedicated socket
while (1) {  // This loop handles one client
    n = read(newsockfd, buffer, 255);
    n = write(newsockfd, "Message received", 16);
}
```

**UDP**: Client address must be captured with each message

```c
// Client address is captured with each message
recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
         (struct sockaddr *)&clientaddr, &len);
// And needed for each response
sendto(sockfd, ack_msg, strlen(ack_msg), 0,
       (const struct sockaddr *)&clientaddr, len);
```

### 5. Message Integrity

**TCP**: Stream-based with no inherent message boundaries

- Multiple `read()` calls may be needed to receive a complete message
- `read()` may return partial messages

**UDP**: Preserves message boundaries

- Each `recvfrom()` returns exactly one complete datagram
- Maximum message size limited by datagram size (typically ~65KB)

### 6. Reliability

**TCP**: Guaranteed delivery with ordering

- Lost packets are retransmitted
- Out-of-order packets are reordered
- Duplicate packets are eliminated

**UDP**: No delivery guarantees

- No retransmission of lost packets
- No packet ordering
- No duplicate elimination

## When to Use Each

**Use TCP when:**

- Data integrity is critical
- Complete delivery must be guaranteed
- Proper sequencing matters
- Applications: Web servers, file transfer, email

**Use UDP when:**

- Speed is more important than reliability
- Real-time applications can tolerate some data loss
- Low overhead is required
- Applications: DNS, streaming media, online games, VoIP

Both have their place in network programming, with the choice depending on the specific requirements of your application.
