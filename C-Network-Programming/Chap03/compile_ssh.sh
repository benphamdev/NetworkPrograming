#!/bin/bash

echo "Compiling SSH port forwarding program..."
gcc -Wall ssh_port_forwarding.c -o ssh_port_forwarding -lssh -pthread

if [ $? -eq 0 ]; then
    echo "Compilation successful."
    echo "Usage: ./ssh_port_forwarding <remote_host> <username> <password>"
    echo "Example: ./ssh_port_forwarding 192.168.255.151 chienpham 1234"
else
    echo "Compilation failed."
fi
