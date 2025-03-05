#!/bin/bash

# Simple compilation script for HTTPS client
echo "Compiling HTTPS simple client..."

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    gcc -o https_simple https_simple.c -lssl -lcrypto
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    gcc -o https_simple https_simple.c -lssl -lcrypto
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # Windows with MinGW
    gcc -o https_simple.exe https_simple.c -lssl -lcrypto -lws2_32
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

if [ $? -eq 0 ]; then
    echo "Compilation successful."
    echo "Usage: ./https_simple <hostname> <port>"
    echo "Example: ./https_simple www.example.com 443"
else
    echo "Compilation failed."
fi