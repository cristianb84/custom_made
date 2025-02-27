#!/bin/bash

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Please use sudo." 
   exit 1
fi

# Check if the PFX file is provided as an argument
if [ $# -eq 0 ]; then
    echo "Usage: $0 <path_to_pfx_file>"
    exit 1
fi

# Input PFX file
PFX_FILE="$1"

# Check if the file exists
if [ ! -f "$PFX_FILE" ]; then
    echo "Error: File '$PFX_FILE' not found!"
    exit 1
fi

# Extract base name from the input file
BASENAME=$(basename -- "$PFX_FILE")
FILENAME="${BASENAME%.*}" # Strip the .pfx extension

# Define file paths
CRT_FILE="/usr/local/share/ca-certificates/${FILENAME}.crt"
KEY_FILE="/etc/ssl/private/${FILENAME}.key"
CLIENT_CERT_DIR="/opt/.cisco/certificates/client"
CLIENT_PRIVATE_DIR="/opt/.cisco/certificates/client/private"

# Extract the certificate
echo "[*] Extracting certificate from '$PFX_FILE' to '$CRT_FILE'..."
openssl pkcs12 -in "$PFX_FILE" -clcerts -nokeys -out "$CRT_FILE" -nodes
if [ $? -ne 0 ]; then
    echo "Error: Failed to extract the certificate."
    exit 1
fi
if [ ! -f "$CRT_FILE" ]; then
    echo "Error: Certificate file '$CRT_FILE' was not created."
    exit 1
fi
echo "[*] Successfully extracted certificate to: $CRT_FILE"

# Extract the private key
echo "[*] Extracting private key to '$KEY_FILE'..."
openssl pkcs12 -in "$PFX_FILE" -nocerts -nodes -out "$KEY_FILE"
if [ $? -ne 0 ]; then
    echo "Error: Failed to extract the private key."
    exit 1
fi
if [ ! -f "$KEY_FILE" ]; then
    echo "Error: Private key file '$KEY_FILE' was not created."
    exit 1
fi
echo "[*] Successfully extracted private key to: $KEY_FILE"

# Ensure correct permissions on private key
chmod 600 "$KEY_FILE"

# Update the CA certificates store
echo "[*] Updating the CA certificates store..."
update-ca-certificates
if [ $? -ne 0 ]; then
    echo "Error: Failed to update the CA certificates."
    exit 1
fi

# Verify that the certificate is listed in the CA store
if grep -q "$FILENAME" /etc/ssl/certs/ca-certificates.crt; then
    echo "[*] Certificate '$FILENAME' successfully added to the CA store!"
else
    echo "Error: Certificate '$FILENAME' not found in the CA store."
    exit 1
fi

# Ensure the Cisco client directories exist
echo "[*] Checking Cisco AnyConnect directories..."
for dir in "$CLIENT_CERT_DIR" "$CLIENT_PRIVATE_DIR"; do
    if [ ! -d "$dir" ]; then
        echo "[*] Directory '$dir' does not exist. Creating it..."
        mkdir -p "$dir"
        if [ $? -ne 0 ]; then
            echo "Error: Failed to create directory '$dir'."
            exit 1
        fi
    fi
done

# Copy files to the Cisco AnyConnect directories
echo "[*] Copying certificate to '$CLIENT_CERT_DIR/'..."
cp "$CRT_FILE" "$CLIENT_CERT_DIR/"
if [ $? -ne 0 ]; then
    echo "Error: Failed to copy the certificate to '$CLIENT_CERT_DIR/'."
    exit 1
fi

echo "[*] Copying private key to '$CLIENT_PRIVATE_DIR/'..."
cp "$KEY_FILE" "$CLIENT_PRIVATE_DIR/"
if [ $? -ne 0 ]; then
    echo "Error: Failed to copy the private key to '$CLIENT_PRIVATE_DIR/'."
    exit 1
fi

echo "[*] Certificate and private key successfully copied to Cisco AnyConnect directories."

# Final success message
echo "[*] Certificate and key installation completed successfully!"
