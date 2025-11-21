#!/bin/bash

# Script to create OpenVPN client configuration using Easy-RSA
# Usage: ./create_openvpn_client.sh <client_name> <output_directory>

set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <client_name> <output_directory>"
    exit 1
fi

CLIENT_NAME=$1
OUTPUT_DIR=$2
EASYRSA_DIR=~/openvpn-ca
SERVER_DIR=/etc/openvpn

# Check if Easy-RSA directory exists
if [ ! -d "$EASYRSA_DIR" ]; then
    echo "Easy-RSA directory not found at $EASYRSA_DIR"
    echo "Installing Easy-RSA and setting up PKI..."

    # Install Easy-RSA
    sudo apt update
    sudo apt install easy-rsa -y

    # Create Easy-RSA directory
    make-cadir $EASYRSA_DIR
    cd $EASYRSA_DIR

    # Initialize PKI and build CA
    ./easyrsa init-pki
    echo "Building CA..."
    ./easyrsa build-ca nopass
else
    cd $EASYRSA_DIR
fi

# Generate client certificate and key
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

# Prepare output directory
mkdir -p $OUTPUT_DIR

# Copy necessary files
cp pki/issued/$CLIENT_NAME.crt $OUTPUT_DIR/
cp pki/private/$CLIENT_NAME.key $OUTPUT_DIR/
cp pki/ca.crt $OUTPUT_DIR/

# Check for TLS auth key
TLS_KEY="$SERVER_DIR/ta.key"
if [ -f "$TLS_KEY" ]; then
    cp $TLS_KEY $OUTPUT_DIR/
fi

# Create client configuration file
CONFIG_FILE="$OUTPUT_DIR/$CLIENT_NAME.ovpn"

cat > $CONFIG_FILE <<EOF
client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3

<ca>
$(cat $OUTPUT_DIR/ca.crt)
</ca>

<cert>
$(cat $OUTPUT_DIR/$CLIENT_NAME.crt)
</cert>

<key>
$(cat $OUTPUT_DIR/$CLIENT_NAME.key)
</key>
EOF

if [ -f "$TLS_KEY" ]; then
    echo "key-direction 1" >> $CONFIG_FILE
    echo "<tls-auth>" >> $CONFIG_FILE
    cat $OUTPUT_DIR/ta.key >> $CONFIG_FILE
    echo "</tls-auth>" >> $CONFIG_FILE
fi

echo "Client configuration and keys have been created in $OUTPUT_DIR"
