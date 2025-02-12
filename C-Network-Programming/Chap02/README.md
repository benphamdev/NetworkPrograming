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


udp

gcc udp_client.c -o udp_client.o