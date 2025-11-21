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
CA_CERT=/etc/openvpn/ca.crt
TLS_KEY=/etc/openvpn/ta.key

# Check if Easy-RSA directory exists
if [ ! -d "$EASYRSA_DIR" ]; then
    echo "Easy-RSA directory not found at $EASYRSA_DIR"
    echo "Installing Easy-RSA and setting up PKI..."

    sudo apt update
    sudo apt install easy-rsa -y

    make-cadir $EASYRSA_DIR
    cd $EASYRSA_DIR

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

# Copy client cert and key
cp pki/issued/$CLIENT_NAME.crt $OUTPUT_DIR/
cp pki/private/$CLIENT_NAME.key $OUTPUT_DIR/

# Copy CA cert from /etc/openvpn
if [ -f "$CA_CERT" ]; then
    cp $CA_CERT $OUTPUT_DIR/
else
    echo "CA certificate not found at $CA_CERT"
    exit 1
fi

# Copy TLS auth key if present
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
$(cat $CA_CERT)
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
    cat $TLS_KEY >> $CONFIG_FILE
    echo "</tls-auth>" >> $CONFIG_FILE
fi

echo "Client configuration created: $CONFIG_FILE"
