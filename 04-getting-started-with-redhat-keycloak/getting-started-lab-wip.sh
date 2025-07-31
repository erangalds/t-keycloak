#!/bin/bash
# Greeting message
echo "Welcome to the Keycloak Getting Started Lab!"
echo "This script will guide you through basic Keycloak operations."
echo ""

# Define common variables for better readability and easier modification
KEYCLOAK_SERVER_URL="https://keycloak:8443"
MASTER_REALM="master"
APP_REALM="my-app-realm"
APP_USER="eranga"
APP_USER_EMAIL="eranga@example.com"
APP_USER_FIRSTNAME="eranga"
APP_USER_LASTNAME="de silva"
APP_USER_PASSWORD="keycloak"
APP_CLIENT_ID="my-web-app"
APP_REDIRECT_URI="http://my-flask-app:8090/callback"
APP_WEB_ORIGIN="http://my-flask-app:8090"
KCADM_PATH="/opt/keycloak/bin/kcadm.sh"

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
"$KCADM_PATH" config credentials \
    --server "$KEYCLOAK_SERVER_URL" \
    --realm "$MASTER_REALM" \
    --user "$KEYCLOAK_ADMIN_USER" \
    --password "$KEYCLOAK_ADMIN_PASSWORD"
if [ $? -ne 0 ]; then
    echo "Error: Keycloak CLI authentication failed. Please check credentials and server URL."
    exit 1
fi
echo "Keycloak CLI authentication complete."
echo ""

# --- Realm Operations ---
echo "--- Realm Operations ---"

echo "Checking for existing realm: '$APP_REALM'..."
# Check if the realm already exists
"$KCADM_PATH" get realms -q realm="$APP_REALM" --fields realm --noquotes &>/dev/null
if [ $? -eq 0 ]; then
    echo "Realm '$APP_REALM' already exists. Skipping creation."
else
    echo "Realm '$APP_REALM' not found. Attempting to create it..."
    "$KCADM_PATH" create realms -s realm="$APP_REALM" -s enabled=true
    if [ $? -eq 0 ]; then
        echo "Realm '$APP_REALM' created successfully."
    else
        echo "Error: Failed to create realm '$APP_REALM'."
        # You might want to exit here if realm creation is critical for subsequent steps
        # exit 1
    fi
fi
echo ""

echo "Listing all realms:"
"$KCADM_PATH" get realms
echo ""

echo "Retrieving only realm names:"
"$KCADM_PATH" get realms --fields realm
echo ""

echo "Retrieving realm name and enabled status:"
"$KCADM_PATH" get realms --fields realm,enabled
echo ""

echo "Retrieving realm ID and name:"
"$KCADM_PATH" get realms --fields id,realm
echo ""

# --- User Operations ---
echo "--- User Operations for Realm '$APP_REALM' ---"

echo "Checking for existing user: '$APP_USER' in realm '$APP_REALM'..."
# Check if the user already exists in the specified realm
"$KCADM_PATH" get users -r "$APP_REALM" -q username="$APP_USER" --fields username --noquotes &>/dev/null
if [ $? -eq 0 ]; then
    echo "User '$APP_USER' already exists in realm '$APP_REALM'. Skipping creation."
else
    echo "User '$APP_USER' not found in realm '$APP_REALM'. Attempting to create it..."
    "$KCADM_PATH" create users \
        -r "$APP_REALM" \
        -s username="$APP_USER" \
        -s enabled=true \
        -s firstName="$APP_USER_FIRSTNAME" \
        -s lastName="$APP_USER_LASTNAME" \
        -s email="$APP_USER_EMAIL"
    if [ $? -eq 0 ]; then
        echo "User '$APP_USER' created successfully in realm '$APP_REALM'."
        echo "Setting password for user '$APP_USER'..."
        "$KCADM_PATH" set-password \
            -r "$APP_REALM" \
            --username "$APP_USER" \
            --new-password "$APP_USER_PASSWORD" \
            #--temporary # Uncomment if you want the user to change it on first login
        if [ $? -eq 0 ]; then
            echo "Password set for user '$APP_USER'."
        else
            echo "Error: Failed to set password for user '$APP_USER'."
        fi
    else
        echo "Error: Failed to create user '$APP_USER' in realm '$APP_REALM'."
    fi
fi
echo ""

echo "Retrieving full details of all users in '$APP_REALM':"
"$KCADM_PATH" get users -r "$APP_REALM"
echo ""

echo "Listing all users with limited fields (username, email, enabled):"
"$KCADM_PATH" get users -r "$APP_REALM" --fields username,email,enabled
echo ""

echo "Filtering and retrieving details for user '$APP_USER':"
"$KCADM_PATH" get users -r "$APP_REALM" --fields username,email,enabled -q username="$APP_USER"
echo ""

# --- Client Operations ---
echo "--- Client Operations for Realm '$APP_REALM' ---"

echo "Checking for existing client: '$APP_CLIENT_ID' in realm '$APP_REALM'..."
# Check if the client already exists in the specified realm
"$KCADM_PATH" get clients -r "$APP_REALM" -q clientId="$APP_CLIENT_ID" --fields clientId --noquotes &>/dev/null
if [ $? -eq 0 ]; then
    echo "Client '$APP_CLIENT_ID' already exists in realm '$APP_REALM'. Skipping creation."
else
    echo "Client '$APP_CLIENT_ID' not found in realm '$APP_REALM'. Attempting to create it..."
    "$KCADM_PATH" create clients \
        -r "$APP_REALM" \
        -s clientId="$APP_CLIENT_ID" \
        -s enabled=true \
        -s clientAuthenticatorType=client-secret \
        -s standardFlowEnabled=true \
        -s directAccessGrantsEnabled=true \
        -s publicClient=false \
        -s redirectUris='["'"$APP_REDIRECT_URI"'"]' \
        -s webOrigins='["'"$APP_WEB_ORIGIN"'"]'
    if [ $? -eq 0 ]; then
        echo "Client '$APP_CLIENT_ID' created successfully in realm '$APP_REALM'."
    else
        echo "Error: Failed to create client '$APP_CLIENT_ID' in realm '$APP_REALM'."
    fi
fi
echo ""

echo "Attempting to retrieve the secret for client '$APP_CLIENT_ID':"
# Getting the Secret of the Client : my-web-app
"$KCADM_PATH" get clients \
    -r "$APP_REALM" \
    -q clientId="$APP_CLIENT_ID" \
    --fields secret \
    --format json \
    | grep "secret" \
    | cut -d':' -f2 \
    | tr -d '", '
echo "Secret retrieval command executed."
echo ""

echo "Extracting the secret for client '$APP_CLIENT_ID' and storing it in a variable..."
# Store the output directly into the KEYCLOAK_CLIENT_SECRET variable
KEYCLOAK_CLIENT_SECRET=$("$KCADM_PATH" get clients \
    -r "$APP_REALM" \
    -q clientId="$APP_CLIENT_ID" \
    --fields secret \
    --format json \
    2>/dev/null \
    | grep "secret" \
    | cut -d':' -f2 \
    | tr -d '", ')

# Check if the secret was successfully captured
if [ -z "$KEYCLOAK_CLIENT_SECRET" ]; then
    echo "Error: Could not retrieve Keycloak client secret. Ensure the client exists and the command runs successfully."
else
    # Display the captured secret
    echo "Keycloak Client Secret captured successfully: $KEYCLOAK_CLIENT_SECRET"
fi
echo ""

echo "Listing all clients with full details in '$APP_REALM':"
"$KCADM_PATH" get clients -r "$APP_REALM"
echo ""

echo "Listing all clients with specific details (clientId, enabled):"
"$KCADM_PATH" get clients -r "$APP_REALM" --fields clientId,enabled
echo ""

echo "Listing clients with Redirect URIs and Web Origins:"
"$KCADM_PATH" get clients -r "$APP_REALM" --fields clientId,enabled,redirectUris,webOrigins
echo ""

echo "Filtering and displaying details for client '$APP_CLIENT_ID':"
"$KCADM_PATH" get clients -r "$APP_REALM" --fields clientId,enabled,redirectUris,webOrigins -q clientId="$APP_CLIENT_ID"
echo ""

echo "--- Getting Started with Keycloak Lab finished ---"