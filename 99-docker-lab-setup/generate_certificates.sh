#!/bin/bash

# Define variables for certificate generation
KEYCLOAK_HOSTNAME="keycloak"
CERT_PASS="password" # This password protects the keystores

# Define the target directory for certificates
CERTS_DIR="certs"

echo "--- Preparing Certificate Directory ---"

# Check if the certs directory exists
if [ -d "$CERTS_DIR" ]; then
  echo "Directory '$CERTS_DIR' found. Clearing its contents..."
  # Delete all contents inside the certs directory, but not the directory itself
  find "$CERTS_DIR" -mindepth 1 -delete
else
  echo "Directory '$CERTS_DIR' not found. Creating it..."
  mkdir -p "$CERTS_DIR"
fi

echo "--- Generating a single Key and Certificate for Keycloak ---"

# 1. Generate a private key (server.key) and a self-signed certificate (server.crt).
# The certificate's CN and SAN must match the hostname used to access Keycloak.
# Here, we include 'keycloak' (for inter-container), 'localhost' (for host access), and '127.0.0.1'.
openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=${KEYCLOAK_HOSTNAME}" \
  -addext "subjectAltName = DNS:${KEYCLOAK_HOSTNAME},DNS:localhost,IP:127.0.0.1" \
  -days 365

echo "Generated server.key and server.crt."

# 2. Create keycloak-cert.pem for the kcadm client to trust. This is just a copy of the public certificate.
cp server.crt keycloak-cert.pem
echo "Created keycloak-cert.pem for client trust."

echo "--- Packaging Certificate into Java Keystores ---"

# 3. Create a PKCS12 keystore from the server key and certificate generated in step 1.
# This format is a standard way to bundle a private key with its certificate chain.
openssl pkcs12 -export -in server.crt -inkey server.key \
  -out keycloak.p12 -name server -passout pass:"${CERT_PASS}"

echo "Generated keycloak.p12 from server.crt and server.key."

# 4. Convert the PKCS12 keystore to a JKS keystore for Keycloak to use.
# This ensures the JKS keystore contains the exact same key and certificate from step 1.
keytool -importkeystore \
  -srckeystore keycloak.p12 -srcstoretype PKCS12 -srcstorepass "${CERT_PASS}" \
  -destkeystore keystore.jks -deststoretype JKS -deststorepass "${CERT_PASS}" \
  -noprompt

echo "Generated keystore.jks from keycloak.p12."

echo "--- Moving Certificates to '$CERTS_DIR' ---"

# Move all generated certificate files into the certs directory
mv server.crt server.key keycloak-cert.pem keystore.jks "$CERTS_DIR/"
# Move the pem file to the flask-app/certs as well. 
cp "${CERTS_DIR}/keycloak-cert.pem" "flask-app/certs/"

echo "Moved generated certificates to '$CERTS_DIR/'"

# Clean up intermediate .p12 file (optional, but good practice for security)
rm keycloak.p12

echo "--- Certificate Generation and Setup Complete ---"