import requests
import json
import os

# Keycloak Configuration
KEYCLOAK_SERVER_URL = "https://keycloak:8443/" # URL of your Keycloak server
KEYCLOAK_REALM = "my-app-realm"
KEYCLOAK_CLIENT_ID = "backend-service"
# !!! IMPORTANT: Get this secret from your Keycloak client settings or CLI output !!!
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "zCFsZQqWKrWxC6LRwewVPKUHmngPMDaI") # Best practice: use env var # Replace with the actual secret

# Path to Keycloak's self-signed certificate for secure communication
KEYCLOAK_CERT_PATH = "/app/certs/keycloak-cert.pem"

# Token endpoint
TOKEN_URL = f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

def get_service_account_token():
    if not KEYCLOAK_CLIENT_SECRET:
        print("Error: BACKEND_SERVICE_CLIENT_SECRET environment variable not set.")
        return None

    payload = {
        "grant_type": "client_credentials",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "scope": "openid" # Can specify scopes for this client if needed
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = None # Initialize response to None to avoid UnboundLocalError
    try:
        response = requests.post(
            TOKEN_URL,
            data=payload,
            headers=headers,
            verify=KEYCLOAK_CERT_PATH # Important for HTTPS with self-signed certs
        )
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        token_data = response.json()
        return token_data.get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"Error obtaining token: {e}")
        # Check if response object exists before trying to access it
        if response is not None:
            print(f"Response: {response.status_code} - {response.text}")
        return None

def access_protected_resource(access_token):
    if not access_token:
        print("No access token available to access resource.")
        return
    
    # URL of the new resource server API running in another container
    protected_api_url = "http://my-resource-api:8091/api/data"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    print(f"\nAttempting to access protected resource at: {protected_api_url}")
    
    response = None
    try:
        # Make the request to the protected API
        response = requests.get(protected_api_url, headers=headers)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        
        print("Successfully accessed protected resource.")
        print(f"Response Status: {response.status_code}")
        print("Data received:")
        print(json.dumps(response.json(), indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Error accessing protected resource: {e}")
        if response is not None:
            print(f"Response: {response.status_code} - {response.text}")

if __name__ == "__main__":
    token = get_service_account_token()
    if token:
        print("Successfully obtained access token for backend service.")
        access_protected_resource(token)
    else:
        print("Failed to obtain access token.")