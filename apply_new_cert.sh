#!/bin/bash
# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Please use sudo." 
   exit 1
fi

# Check if the PFX file is provided as an argument
if [ $# -eq 0 ]; then
    echo "Usage: $0 <path_to_pfx_file> [pfx_password]"
    exit 1
fi

# Input PFX file
PFX_FILE="$1"
PFX_PASSWORD="$2"

# Check if the file exists
if [ ! -f "$PFX_FILE" ]; then
    echo "Error: File '$PFX_FILE' not found!"
    exit 1
fi

# Extract base name from the input file
BASENAME=$(basename -- "$PFX_FILE")
FILENAME="${BASENAME%.*}"

# Define file paths
CRT_FILE="/usr/local/share/ca-certificates/${FILENAME}.crt"
KEY_FILE="/etc/ssl/private/${FILENAME}.key"
CLIENT_CERT_DIR="/opt/.cisco/certificates/client"
CLIENT_PRIVATE_DIR="/opt/.cisco/certificates/client/private"

# Prepare password parameter
if [ -n "$PFX_PASSWORD" ]; then
    PASS_PARAM="-passin pass:$PFX_PASSWORD"
else
    PASS_PARAM=""
fi

# Extract the certificate
echo "[*] Extracting certificate from '$PFX_FILE' to '$CRT_FILE'..."
if ! openssl pkcs12 -in "$PFX_FILE" $PASS_PARAM -clcerts -nokeys -out "$CRT_FILE" -nodes; then
    echo "Error: Failed to extract the certificate."
    exit 1
fi

if [ ! -f "$CRT_FILE" ]; then
    echo "Error: Certificate file '$CRT_FILE' was not created."
    exit 1
fi
echo "[*] Successfully extracted certificate to: $CRT_FILE"

# Extract the private key (reuse password so it doesn't prompt again)
echo "[*] Extracting private key to '$KEY_FILE'..."
if ! openssl pkcs12 -in "$PFX_FILE" $PASS_PARAM -nocerts -nodes -out "$KEY_FILE"; then
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
if ! update-ca-certificates; then
    echo "Warning: Failed to update the CA certificates store."
    echo "         Continuing anyway as this may not be critical..."
fi

# Better verification - check if the .pem file was created
PEM_FILE="/etc/ssl/certs/${FILENAME}.pem"
if [ -f "$PEM_FILE" ]; then
    echo "[*] Certificate '$FILENAME' successfully added to the CA store!"
elif [ -f "/etc/ssl/certs/${FILENAME}.crt" ]; then
    echo "[*] Certificate '$FILENAME' found in CA certs directory!"
else
    echo "[*] Warning: Certificate verification uncertain, but continuing..."
fi

# Ensure the Cisco client directories exist
echo "[*] Checking Cisco AnyConnect directories..."
for dir in "$CLIENT_CERT_DIR" "$CLIENT_PRIVATE_DIR"; do
    if [ ! -d "$dir" ]; then
        echo "[*] Directory '$dir' does not exist. Creating it..."
        if ! mkdir -p "$dir"; then
            echo "Error: Failed to create directory '$dir'."
            exit 1
        fi
    fi
done

# Copy files to the Cisco AnyConnect directories
echo "[*] Copying certificate to '$CLIENT_CERT_DIR/'..."
if ! cp "$CRT_FILE" "$CLIENT_CERT_DIR/"; then
    echo "Error: Failed to copy the certificate to '$CLIENT_CERT_DIR/'."
    exit 1
fi

echo "[*] Copying private key to '$CLIENT_PRIVATE_DIR/'..."
if ! cp "$KEY_FILE" "$CLIENT_PRIVATE_DIR/"; then
    echo "Error: Failed to copy the private key to '$CLIENT_PRIVATE_DIR/'."
    exit 1
fi

# Set proper permissions on copied files
chown $SUDO_USER:$SUDO_USER "$CLIENT_CERT_DIR/${FILENAME}.crt"
chown $SUDO_USER:$SUDO_USER "$CLIENT_PRIVATE_DIR/${FILENAME}.key"
chmod 644 "$CLIENT_CERT_DIR/${FILENAME}.crt"
chmod 600 "$CLIENT_PRIVATE_DIR/${FILENAME}.key"

echo "[*] Certificate and private key successfully copied to Cisco AnyConnect directories."
echo "[*] Certificate and key installation completed successfully!"
echo ""
echo "Certificate: $CLIENT_CERT_DIR/${FILENAME}.crt"
echo "Private Key: $CLIENT_PRIVATE_DIR/${FILENAME}.key"
