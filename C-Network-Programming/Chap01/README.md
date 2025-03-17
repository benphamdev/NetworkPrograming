### Exercise 1: Server-Client Connection and Payload Display

#### Description

This exercise requires you to create a server and client program to connect with each other and display the payload of
the received packets.

#### Related File

- `ether.c` `ls_ifaces.o`

#### Instructions

1. **Server**: Run the server program to listen for Ethernet packets and display detailed information about these
   packets, including source MAC address, destination MAC address, Ethernet type, and payload.
2. **Client**: Run the client program to send packets to the server.

#### How to Run

1. Compile the server program:

   ```sh
   gcc ether.c -o ether.o
   ```

2. Run the server program:

   ```sh
   ./ether.o
   ```

### Exercise 2: Sending and Receiving Messages between Server and Client

1. Compile the server program:

   ```sh
   gcc ether_dump.c -o ether_dump.o
   ```

2. Run the server program:

   ```sh
   ./ether_dump.o
   ```

3. Compile the client program:

   ```sh
   gcc ether_send.c -o ether_send.o
   ```

4. Run the client program:

   ```sh
   ./ether_send.o
   ```

To send a specific message with a source MAC address to the server, you can use the following command:

```sh
   ./ether_send.o 02:42:AC:14:00:65  "hello chien pham"
```

This command sends the message "hello chien pham" to the server with the specified source MAC address.

Run the server program with IP header display:

```sh
   ./ether_dump.o -i
```

Summary
This README provides detailed instructions on how to compile and run the server and client programs for both exercises.
It also includes example commands for sending messages and displaying additional information such as the IP header

Makefilechange indentation in vscode:
<https://bobbyhadz.com/blog/vscode-change-indentation>
sed -i 's/^ /\t/'
