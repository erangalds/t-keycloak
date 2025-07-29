import requests
import json
import os

# Keycloak Configuration
KEYCLOAK_SERVER_URL = "https://keycloak:8443/" # URL of your Keycloak server
KEYCLOAK_REALM = "my-app-realm"
KEYCLOAK_CLIENT_ID = "backend-service"
# !!! IMPORTANT: Get this secret from your Keycloak client settings or CLI output !!!
KEYCLOAK_CLIENT_SECRET = "YOUR_GENERATED_SECRET_FOR_BACKEND_SERVICE" # Replace with the actual secret

# Token endpoint
TOKEN_URL = f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

def get_service_account_token():
    payload = {
        "grant_type": "client_credentials",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "scope": "openid" # Can specify scopes for this client if needed
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(TOKEN_URL, data=payload, headers=headers)
        response.raise_for_status() # Raise an exception for HTTP errors
        token_data = response.json()
        return token_data.get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"Error obtaining token: {e}")
        if response:
            print(f"Response: {response.status_code} - {response.text}")
        return None

def access_protected_resource(access_token):
    if not access_token:
        print("No access token available to access resource.")
        return

    # In a real scenario, this would be your protected API endpoint
    # For demonstration, we'll just print the token.
    print(f"\nAccessing hypothetical protected resource with token:\n{access_token[:30]}...{access_token[-10:]}")
    # Example:
    # protected_api_url = "http://your-resource-server/api/data"
    # headers = {"Authorization": f"Bearer {access_token}"}
    # response = requests.get(protected_api_url, headers=headers)
    # print(f"Protected resource response: {response.status_code} - {response.text}")

if __name__ == "__main__":
    token = get_service_account_token()
    if token:
        print("Successfully obtained access token for backend service.")
        access_protected_resource(token)
    else:
        print("Failed to obtain access token.")