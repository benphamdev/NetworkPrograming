#!/bin/bash

echo "Compiling SSH remote port forwarding web server..."
gcc -Wall -o ssh_remote_port_forwarding ssh_remote_port_forwarding.c -lssh

if [ $? -eq 0 ]; then
    echo "Compilation successful."
    echo "Usage: ./ssh_remote_port_forwarding <ssh_server> <username> <password>"
    echo "Example: ./ssh_remote_port_forwarding 192.168.255.151 chienpham password123"
    echo ""
    echo "This program will:"
    echo "1. Connect to the SSH server"
    echo "2. Set up remote port forwarding from the SSH server's port 8080 to your local machine"
    echo "3. Serve a simple web page to anyone who connects to the SSH server on port 8080"
    echo ""
    echo "To test, from a third machine, connect to: http://ssh_server_ip:8080"
else
    echo "Compilation failed."
fi

chmod +x ssh_remote_port_forwarding
