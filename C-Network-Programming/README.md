# C-Network-Programming

## Description

## Author

This project is maintained by [Phạm Duy Chiến](https://github.com/benphamdev).

This project focuses on network programming using C. It includes exercises to create server-client connections, display payloads of received packets, and send/receive messages between server and client. The motivation behind this project is to understand the fundamentals of network communication and packet handling.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Credits](#credits)
- [License](#license)

## Installation

To run the project using Docker Compose, use the following command:

```sh
docker compose -f ./docker-compose_c1.yaml -p network-container up -d
```

## Usage

### Exercise 1: Server-Client Connection and Payload Display

#### Description

This exercise requires you to create a server and client program to connect with each other and display the payload of the received packets.

#### Related File

- `ether.c` `ls_ifaces.o`

#### Instructions

1. **Server**: Run the server program to listen for Ethernet packets and display detailed information about these packets, including source MAC address, destination MAC address, Ethernet type, and payload.
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
   gcc server.c -o server.o
   ```

2. Run the server program:

   ```sh
   ./server.o
   ```

3. Compile the client program:

   ```sh
   gcc client.c -o client.o
   ```

4. Run the client program:

   ```sh
   ./client.o
   ```

## Credits

List your collaborators, if any, with links to their GitHub profiles.

## License

The last section of a high-quality README file is the license. This lets other developers know what they can and cannot do with your project. If you need help choosing a license, refer to [https://choosealicense.com/](https://choosealicense.com/).

## Badges

![badmath](https://img.shields.io/github/languages/top/lernantino/badmath)

## Features

If your project has a lot of features, list them here.

## How to Contribute

If you created an application or package and would like other developers to contribute it, you can include guidelines for how to do so. The [Contributor Covenant](https://www.contributor-covenant.org/) is an industry standard, but you can always write your own if you'd prefer.

## Tests

Go the extra mile and write tests for your application. Then provide examples on how to run them here.
