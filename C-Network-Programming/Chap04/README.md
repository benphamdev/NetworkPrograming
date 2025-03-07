# Network Programming Setup Guide

## Basic Setup

### Install Required Packages

```bash
# Update package lists
sudo apt update

# Install OpenSSL, build-essential (compiler tools), and libssh development libraries
sudo apt install -y openssl libssl-dev build-essential libssh-dev

# Install additional network tools
sudo apt install -y curl tshark tcpdump nmap netcat-traditional
```

### Verify Installations

```bash
gcc --version
openssl version
pkg-config --modversion libssh
curl --version
tshark --version
```

## Compilation Examples

### SSH Port Forwarding

```bash
gcc -o ssh_port_forwarding ssh_port_forwarding.c -lssh -lpthread
```

### HTTP Server with Threading

```bash
gcc http_server_v2.c -o http_server_v2.o -pthread
```

### HTTPS Server

```bash
gcc https_server.c -o https_server -lssl -lcrypto -pthread
```

## Working with OpenSSL Certificates

### Fixing the RANDFILE Issue

OpenSSL may require a seed file for random number generation. Here are several solutions:

#### Option 1: Create the seed file manually (simplest fix)

```bash
# Create an empty file
touch ~/.rnd

# Set proper permissions
chmod 600 ~/.rnd
```

#### Option 2: Set the RANDFILE environment variable

```bash
export RANDFILE=/dev/null
```

#### Option 3: Use the OPENSSL_RAND_SEED environment variable

```bash
OPENSSL_RAND_SEED=1 openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

#### Option 4: For a permanent fix, add to your .bashrc

```bash
echo 'export RANDFILE=/dev/null' >> ~/.bashrc
source ~/.bashrc
```

### Creating and Managing SSL Certificates

```bash
# Generate a self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

# View certificate information
openssl x509 -in cert.pem -text -noout

# Verify private key
openssl rsa -in key.pem -check
```

## Network Analysis

```bash
# Capture TLS handshake packets
sudo tshark -i eth0 -f "tcp port 9443" -Y "tls.handshake"
```

## Running Examples

### HTTPS Server

```bash
./https_server
```

### HTTPS Simple Client

```bash
chmod +x compile_https_simple.sh
./compile_https_simple.sh
./https_simple google.com 443
```

