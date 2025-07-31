#!/bin/bash
# Greeting message
echo "Welcome to the Keycloak Getting Started Lab!"
echo "This script will guide you through basic Keycloak operations."
echo ""

# Check if environment variables are set
if [ -z "$KEYCLOAK_ADMIN_USER" ] || [ -z "$KEYCLOAK_ADMIN_PASSWORD" ]; then
    echo "Error: Please set the KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASSWORD environment variables."
    echo "Example: export KEYCLOAK_ADMIN_USER=admin"
    echo "Example: export KEYCLOAK_ADMIN_PASSWORD=admin"
    exit 1
fi
# Display the admin user being used
echo "Using Keycloak admin user: $KEYCLOAK_ADMIN_USER"
echo ""

# --- Authentication ---
echo "--- Authenticating into Keycloak CLI ---"
/opt/keycloak/bin/kcadm.sh config credentials \
    --server https://keycloak:8443 \
    --realm master \
    --user "$KEYCLOAK_ADMIN_USER" \
    --password "$KEYCLOAK_ADMIN_PASSWORD"
echo "Keycloak CLI authentication complete."
echo ""

# --- Realm Operations ---
echo "--- Realm Operations ---"

echo "Attempting to create a new realm: 'my-app-realm'..."
/opt/keycloak/bin/kcadm.sh create realms -s realm=my-app-realm -s enabled=true
echo "Realm 'my-app-realm' creation initiated. (Note: May show error if realm already exists)"
echo ""

echo "Listing all realms:"
/opt/keycloak/bin/kcadm.sh get realms
echo ""

echo "Retrieving only realm names:"
/opt/keycloak/bin/kcadm.sh get realms --fields realm
echo ""

echo "Retrieving realm name and enabled status:"
/opt/keycloak/bin/kcadm.sh get realms --fields realm,enabled
echo ""

echo "Retrieving realm ID and name:"
/opt/keycloak/bin/kcadm.sh get realms --fields id,realm
echo ""

# --- User Operations ---
echo "--- User Operations for Realm 'my-app-realm' ---"

echo "Attempting to create user 'eranga' in 'my-app-realm'..."
/opt/keycloak/bin/kcadm.sh create users \
    -r my-app-realm \
    -s username=eranga \
    -s enabled=true \
    -s firstName=eranga \
    -s lastName="de silva" \
    -s email=eranga@example.com
echo "User 'eranga' creation initiated. (Note: May show error if user already exists)"
echo ""

echo "Setting password for user 'eranga'..."
/opt/keycloak/bin/kcadm.sh set-password \
    -r my-app-realm \
    --username eranga \
    --new-password "keycloak"
    # To make password temporary, uncomment the line below:
    # --temporary
echo "Password set for user 'eranga'."
echo ""

echo "Retrieving full details of all users in 'my-app-realm':"
/opt/keycloak/bin/kcadm.sh get users -r my-app-realm
echo ""

echo "Listing all users with limited fields (username, email, enabled):"
/opt/keycloak/bin/kcadm.sh get users -r my-app-realm --fields username,email,enabled
echo ""

echo "Filtering and retrieving details for user 'eranga':"
/opt/keycloak/bin/kcadm.sh get users -r my-app-realm --fields username,email,enabled -q username=eranga
echo ""

# --- Client Operations ---
echo "--- Client Operations for Realm 'my-app-realm' ---"

echo "Attempting to create client 'my-web-app' in 'my-app-realm'..."
/opt/keycloak/bin/kcadm.sh create clients \
    -r my-app-realm \
    -s clientId=my-web-app \
    -s enabled=true \
    -s clientAuthenticatorType=client-secret \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=true \
    -s publicClient=false \
    -s redirectUris='["http://my-flask-app:8090/callback"]' \
    -s webOrigins='["http://my-flask-app:8090"]'
echo "Client 'my-web-app' creation initiated. (Note: May show error if client already exists)"
echo ""

echo "Attempting to retrieve the secret for client 'my-web-app':"
# Getting the Secret of the Client : my-web-app
/opt/keycloak/bin/kcadm.sh get clients \
    -r my-app-realm \
    -q clientId=my-web-app \
    --fields secret \
    --format json \
    | grep "secret" \
    | cut -d':' -f2 \
    | tr -d '", '
echo "Secret retrieval command executed."
echo ""

echo "Extracting the secret for client 'my-web-app' and storing it in a variable..."
# Store the output directly into the KEYCLOAK_CLIENT_SECRET variable
KEYCLOAK_CLIENT_SECRET=$(/opt/keycloak/bin/kcadm.sh get clients \
    -r my-app-realm \
    -q clientId=my-web-app \
    --fields secret \
    --format json \
    | grep "secret" \
    | cut -d':' -f2 \
    | tr -d '", ')

# Check if the secret was successfully captured
if [ -z "$KEYCLOAK_CLIENT_SECRET" ]; then
    echo "Error: Could not retrieve Keycloak client secret."
else
    # Display the captured secret
    echo "Keycloak Client Secret captured successfully: $KEYCLOAK_CLIENT_SECRET"
fi
echo ""

echo "Listing all clients with full details in 'my-app-realm':"
/opt/keycloak/bin/kcadm.sh get clients -r my-app-realm
echo ""

echo "Listing all clients with specific details (clientId, enabled):"
/opt/keycloak/bin/kcadm.sh get clients -r my-app-realm --fields clientId,enabled
echo ""

echo "Listing clients with Redirect URIs and Web Origins:"
/opt/keycloak/bin/kcadm.sh get clients -r my-app-realm --fields clientId,enabled,redirectUris,webOrigins
echo ""

echo "Filtering and displaying details for client 'my-web-app':"
/opt/keycloak/bin/kcadm.sh get clients -r my-app-realm --fields clientId,enabled,redirectUris,webOrigins -q clientId=my-web-app
echo ""

echo "--- Getting Started with Keycloak Lab finished ---"