# Client Credential Flow (Machine to Machine Flow)

This flow is used when an application needs to access resources on its own behalf, without a specific user being involved. For instance, a backend service calling another backend service.

## Concept

1. **Client authenticates directly with Keycloak** using its `client_id` and `client_secret`.
    
2. **Keycloak issues an `access_token`** directly to the client. No user interaction or redirect is involved.
    
3. **Client uses the `access_token`** to access protected resources.

## Implementation (Keycloak Setup)

We need a new client for this example. This time we need to create a client with `serviceAccountEnabled=True`. 

Let me loginto the keycloak cli container and create a new client.

1. Authenticate with the Keycloak server as the admin user. 

    ```bash
    /opt/keycloak/bin/kcadm.sh config credentials \
      --server https://keycloak:8443 \
      --realm master \
      --user $KEYCLOAK_ADMIN_USER \
      --password $KEYCLOAK_ADMIN_PASSWORD
    ```



2. Create a new client. 

    ```bash
    /opt/keycloak/bin/kcadm.sh create clients \
        -r my-app-realm \
        -s clientId=backend-service \
        -s enabled=true \
        -s clientAuthenticatorType=client-secret \
        -s serviceAccountsEnabled=true \
        -s standardFlowEnabled=false \
        -s directAccessGrantsEnabled=false \
        -s publicClient=false
    ```

    This command uses `kcadm.sh`, the Keycloak Admin CLI, to create a new **client** within a specified Keycloak realm. Let's break down each part of the command:

    - `create clients`: This tells `kcadm.sh` to perform a "create" operation on the "clients" resource. In Keycloak, a "client" represents any application or service that needs to authenticate users or obtain tokens from Keycloak. This could be a web application, a mobile app, a backend service, etc.
    
    - `-r my-app-realm`:
        
        -  `-r` is short for `--realm`.
        
        - `my-app-realm`: This specifies the Keycloak realm where the new client will be created. A realm in Keycloak is a logical partition where users, roles, and clients are managed. It's like a tenancy or a separate environment within your Keycloak instance.
        
    - `-s clientId=backend-service`:
        
        - `-s` is short for `--set`. This option is used to set specific attributes or properties of the resource being created or updated.
        
        - `clientId=backend-service`: This sets the `clientId` for the new client. The `clientId` is a unique identifier for your application within the realm, and it's what your application will use to identify itself to Keycloak when requesting authentication or tokens. Here, it's named `backend-service`, suggesting this client is for a backend application or service.
        
    - `-s enabled=true`:
        
        - `enabled=true`: This sets the client to be enabled immediately after creation, meaning it can be used for authentication and authorization requests.
        
    - `-s clientAuthenticatorType=client-secret`:
        
        - `clientAuthenticatorType=client-secret`: This defines how this client will authenticate itself to Keycloak when making direct requests (e.g., token exchange).
            
            - `client-secret` means that the client will use a shared secret (a password-like string) that is known only to the client and Keycloak. This is typical for "confidential clients" like backend services or traditional web applications that can securely store a secret. Other types include `public` (for clients like single-page applications or mobile apps that cannot securely store a secret) and `jwt` (for authentication with a JWT).
            
    - `-s serviceAccountsEnabled=true`:
        
        - `serviceAccountsEnabled=true`: This is a very important setting for backend services. When `serviceAccountsEnabled` is true, Keycloak automatically creates a "service account" for this client. A service account is essentially a "user" that represents the client itself, not a human user. This allows the backend service to obtain its own access tokens (using the "Client Credentials Grant" in OAuth2) to access other protected resources directly, without a human user being involved. This is ideal for machine-to-machine communication.
        
    - `-s standardFlowEnabled=false`:
        
        - `standardFlowEnabled=false`: The "Standard Flow" (also known as Authorization Code Flow) is the most common OAuth2 flow for web applications where a human user is present in a browser. It involves redirecting the user to Keycloak for login. By setting this to `false`, you are explicitly stating that this `backend-service` client will _not_ be used for interactive user logins via a browser. This aligns with its role as a backend service.
        
    - `-s directAccessGrantsEnabled=false`:
        
        - `directAccessGrantsEnabled=false`: The "Direct Access Grants" flow (also known as Resource Owner Password Credentials Grant) allows a client to directly exchange a user's username and password for tokens. This flow is generally **discouraged** due to security risks (it requires the client to handle user credentials). Setting it to `false` is a good security practice, especially for a backend service that shouldn't be handling user passwords directly.
        
    - `-s publicClient=false`:
        
        - `publicClient=false`: This explicitly marks the client as a **confidential client**. Confidential clients are applications that can be trusted to securely store a client secret (like a server-side application). This contrasts with "public clients" (like SPAs or mobile apps) that cannot guarantee the confidentiality of a secret and therefore don't use one. This setting aligns with `clientAuthenticatorType=client-secret`.
        

3. Get the Client Secret

    Now le me get the client secret. 

    ```bash
    /opt/keycloak/bin/kcadm.sh get clients \
        -r my-app-realm \
        -q clientId=backend-service \
        --fields secret \
        --format json \
        | grep "secret" \
        | cut -d':' -f2 \
        | tr -d '", '
    # zCFsZQqWKrWxC6LRwewVPKUHmngPMDaI
    ```

4. Assign roles to the service account (Optional but a good practice)

    Keycloak automatically creates a service account user for clients with `serviceAccountsEnabled=true`. We can assign roles to this service account. Let's create a realm role `backend-access` and assign it.

    ```bash
    # Create the realm role
    /opt/keycloak/bin/kcadm.sh create roles \
        -r my-app-realm \
        -s name=backend-access
    
    # Get the service account user ID for 'backend-service'
    SERVICE_ACCOUNT_USER_ID=$(/opt/keycloak/bin/kcadm.sh get users \
        -r my-app-realm \
        -q username=service-account-backend-service \
        --fields id \
        --format json \
        | grep -oP '"id"\s*:\s*"\K[^"]+' \
        | head -1)

    # Get tge realm role ID for 'backend-access'
    REALM_ROLE_ID=$(/opt/keycloak/bin/kcadm.sh get roles \
        -r my-app-realm \
        -q name=backend-access \
        --fields id \
        --format json \
        | grep -oP '"id"\s*:\s*"\K[^"]+' \
        | head -1)

    # Assign the role to the service account
    /opt/keycloak/bin/kcadm.sh add-roles \
        -r my-app-realm \
        --uusername "service-account-backend-service" \
        --rolename "backend-access" \
    ```
    
5. Create the Resource Server Client (my-resource-api)

    The `backend-service` will call a protected API. This API is our "Resource Server". We must also register it as a client in Keycloak so that Keycloak is aware of it. We configure it as a `bearer-only` client, which is the correct type for a service that only verifies tokens and never initiates logins itself.

    ```bash
    # Create the resource server client
    /opt/keycloak/bin/kcadm.sh create clients \
        -r my-app-realm \
        -s clientId=my-resource-api \
        -s enabled=true \
        -s bearerOnly=true \
        -s description="Resource Server API that serves protected data"

    # Get its Client Secret
    /opt/keycloak/bin/kcadm.sh get clients \
        -r my-app-realm \
        -q clientId=my-resource-api \
        --fields secret \
        --format json \
        | grep "secret" \
        | cut -d':' -f2 \
        | tr -d '", '
    # We don't get a secret for this client
    
    ```


## Python Code Implementation

### Code Break Down (Backend Service:`backend_client.py`)

```python
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
```

Imagine we have a club, and to enter, we need a special ID card. This ID card proves who we are and what we're allowed to do inside the club.

1. The Players Involved

    - **Keycloak Server:** Our "ID card office." It's where the authentication happens and where access tokens are issued. In our code, this is `KEYCLOAK_SERVER_URL`.
    
    - **Backend Service (Your Python Script):** This is the application that needs an "ID card." It's a "client" in OAuth 2.0 terms. In our code, this is identified by `KEYCLOAK_CLIENT_ID` ("backend-service") and `KEYCLOAK_CLIENT_SECRET`.
    
    - **Resource Server (Hypothetical):** This is the application or API that holds the protected data or functionality. To access it, we need a valid "ID card" (access token). In our code, this is represented by the commented-out `protected_api_url`.
    
    - **Realm:** In Keycloak, a realm is like a separate isolated space for managing users, clients, roles, etc. It's good for multi-tenancy or separating different applications. Our code uses `KEYCLOAK_REALM` ("my-app-realm").
    
    - **Client ID:** A unique identifier for our backend service within Keycloak.
    
    - **Client Secret:** A secret password that only our backend service and Keycloak know. It's used to prove the identity of the backend service when it asks for an access token. **It's crucial to keep this secret secure!** 
    
    - **Access Token:** The "ID card" itself. It's a string (often a JSON Web Token or JWT) that contains information about the client and its permissions. It's usually short-lived.


2. The Client Credentials Flow
    
    Let me explain now how the backend service get's its "ID Card"

    1. Backend Service (Client) Requests an ID Card:

        - In my python script I make a POST request to the Keycloak server's token endpoint.(`TOKEN_URL`)

        - In this request, I include below: 
            - `grant_type=client_credentials`: Which tells keycloak serer how the client needs to be authenticated. 

            -  `client_id:backend-service` : Client's unique identifier

            - `client_secret:zCFxxxxxxx`: The secret password for the client given by the keycloak server when the client was registered within keycloak. 
            
            - `scope:openid`: This is optional, but it asks for basic information about the client's identity

    2. Keycloak verifies the Identity:

        - Keycloak receives the request

        - It checks if the `client_id` and `client_secret` match what it has on record for `backend-service` in the `my-app-realm`.

    3. Keycloak Issues an ID Card (Access Token):

        - If the credentials are valid, Keycloak generates an `access_token` and sends it back to our backend service. This token is usually a **JWT (JSON Web Token)** which is a digitally signed, compact, URL-safe means of representing claims to be transferred between two parties.


3.  `get_service_account_token` function Code Break Down

    - **`KEYCLOAK_SERVER_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`:** These are the configuration details for connecting to Keycloak. Notice the important note about the `KEYCLOAK_CLIENT_SECRET`
    
    - **`KEYCLOAK_CERT_PATH`:** This is crucial for **secure communication (HTTPS)**. Since I have configured the keycloak app with a self signed certificate we need to use this certificate. 

    - **`TOKEN_URL`:** This is the specific endpoint on the Keycloak server where clients request tokens.

    - **`payload`:** This dictionary holds the data sent in the `POST` request to Keycloak, as described in the "Client Credentials Grant Flow" section.
        
        - `grant_type: "client_credentials"`: Specifies the OAuth 2.0 flow being used.
        
        - `client_id`: Identifies the client making the request.
        
        - `client_secret`: The secret used to authenticate the client.
        
        - `scope: "openid"`: Requests the `openid` scope, which is often used with OpenID Connect, a layer on top of OAuth 2.0 for identity.

    - **`headers`:** Specifies the content type of the data being sent (`application/x-www-form-urlencoded` is standard for this type of OAuth 2.0 request).
        
    - **`requests.post(...)`:** This line actually sends the HTTP POST request to Keycloak.

        - `data=payload`: Sends the `payload` as form-urlencoded data.

        - `headers=headers`: Includes the specified headers.
        
        - `verify=KEYCLOAK_CERT_PATH`: This tells the `requests` library to verify the SSL certificate presented by the Keycloak server using the certificate found at `KEYCLOAK_CERT_PATH`. 

    - **`response.raise_for_status()`:** This is a good practice. If Keycloak responds with an error status code (like 400 for a bad request or 500 for a server error), this line will immediately raise an exception, preventing the code from proceeding with invalid data.
    
    - **`token_data = response.json()`:** If the request is successful, Keycloak sends back a JSON response containing the `access_token` (and often `expires_in`, `token_type`, etc.). This line parses that JSON.

    - **`token_data.get("access_token")`:** Extracts the actual access token string from the JSON response.
    
    - **`try...except requests.exceptions.RequestException as e:`:** This is error handling. If anything goes wrong during the HTTP request (e.g., network issue, Keycloak server is down, invalid URL), this block catches the error and prints a helpful message. 

4.  `access_protected_resource` function Code Break Down

    This function takes the obtained `access_token` and uses it to call the protected `/api/data` endpoint on our `my-resource-api` service.

    - **`protected_api_url`**: This is the internal URL for our resource server. Since both services are running in the same Docker network (`keycloak_net`), they can communicate using their service names as hostnames (e.g., `http://my-resource-api:8091`).

    - **`headers`**: A dictionary is created to hold the HTTP headers. The crucial part is the `Authorization` header, which is set to `Bearer <your_access_token>`. This is the standard way to present a JWT for authorization.

    - **`requests.get(...)`**: This sends the actual HTTP GET request to the protected API.

    - **`response.raise_for_status()`**: A best practice that checks if the response has a successful status code (2xx). If it receives an error code (4xx or 5xx), it will raise an exception, which is caught by the `try...except` block.
    
    - **`json.dumps(response.json(), indent=2)`**: If the request is successful, the function prints the JSON data received from the protected API, demonstrating that the entire flow worked.
    
    - **Error Handling**: The `try...except` block ensures that if the API call fails (e.g., the resource server is down, or the token is rejected), a clear error message is printed.

### Code Break Down of Resour Server (my-resource-api: `resource_server.py`)

```python
from flask import Flask, request, jsonify
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakInvalidTokenError
import functools

# Initialize Flask app
app = Flask(__name__)

# --- Keycloak Configuration ---
# These should match your Keycloak instance and realm
KEYCLOAK_SERVER_URL = "https://keycloak:8443/"
KEYCLOAK_REALM = "my-app-realm"

# The audience claim in the token from backend_client.py will be 'backend-service'.
# We must verify that the token was intended for this audience.
KEYCLOAK_AUDIENCE = "backend-service"

# The client ID for this resource server.
# The python-keycloak library needs a client_id to initialize,
RESOURCE_SERVER_CLIENT_ID = "my-resource-api"

# Path to Keycloak's self-signed certificate for secure communication
KEYCLOAK_CERT_PATH = "/app/certs/keycloak-cert.pem"

# Initialize KeycloakOpenID client for token validation
keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    realm_name=KEYCLOAK_REALM,
    client_id=RESOURCE_SERVER_CLIENT_ID,
    verify=KEYCLOAK_CERT_PATH
)

# --- Token Validation Decorator ---
def token_required(func):
    """A decorator to protect routes with Keycloak token validation."""
    @functools.wraps(func)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Authorization header is missing"}), 401

        parts = auth_header.split()
        if parts[0].lower() != 'bearer' or len(parts) != 2:
            return jsonify({"error": "Authorization header must be in 'Bearer <token>' format"}), 401

        token = parts[1]
        
        try:
            # Decode and validate the token.
            # The library automatically fetches the realm's public key to verify the signature.
            # It also verifies the token's expiration and audience by default.
            token_info = keycloak_openid.decode_token(
                token,
                validate=True
            )
        except KeycloakInvalidTokenError as e:
            return jsonify({"error": "Invalid token", "message": str(e)}), 401
        except Exception as e:
            return jsonify({"error": "Failed to validate token", "message": str(e)}), 500

        return func(token_info, *args, **kwargs)
    return decorated_function

# --- Protected API Route ---
@app.route("/api/data", methods=["GET"])
@token_required
def get_protected_data(token_info):
    """
    An example protected endpoint. It only runs if the @token_required decorator
    successfully validates the token.
    """
    # If validation passes, return the protected data
    sample_data = {
        "message": "Access granted to protected data!",
        "data": [
            {"id": 1, "value": "secret_data_1"},
            {"id": 2, "value": "secret_data_2"}
        ],
        "authenticated_client": token_info.get('clientId'),
        "token_audience": token_info.get('aud')
    }
    return jsonify(sample_data)

if __name__ == "__main__":
    # For production, use a proper WSGI server like Gunicorn or uWSGI
    app.run(host="0.0.0.0", port=8091, debug=True)
```

1. **Imports:**

    - `from flask import Flask, request, jsonify`: Imports necessary components from the Flask framework:
        - `Flask`: The main Flask application class.
        
        - `request`: Object to access incoming request data (like headers).
        
        - `jsonify`: Helper to return JSON responses.
        
    - `from keycloak import KeycloakOpenID`: Imports the `KeycloakOpenID` client from the `python-keycloak`library, used for interacting with Keycloak.
    
    - `from keycloak.exceptions import KeycloakInvalidTokenError`: Imports a specific exception for handling invalid Keycloak tokens.
    
    - `import functools`: Used for `functools.wraps` in the decorator to preserve metadata of the decorated function.
    

2. **Flask App Initialization:**

    - `app = Flask(__name__)`: Creates an instance of the Flask application.
    

3. **Keycloak Configuration:**

    This section defines constants for configuring the connection to our Keycloak instance:

    - `KEYCLOAK_SERVER_URL = "https://keycloak:8443/"`: The base URL of our Keycloak server. 
    
    - `KEYCLOAK_REALM = "my-app-realm"`: The name of the Keycloak realm where our clients and users are managed.
    
    - `KEYCLOAK_AUDIENCE = "backend-service"`: This is a crucial security aspect. The `aud` (audience) claim in a JWT specifies the intended recipient of the token. Here, it's set to `backend-service` meaning that tokens issued for this backend service must have this audience to be considered valid by this application. This helps prevent tokens intended for other services from being used here. But in my example here, due to some configuration being missing, I didn't get the `clientID` nor the `aud` properly. 
    
    - `RESOURCE_SERVER_CLIENT_ID = "my-resource-api"`: The client ID registered in Keycloak for this specific resource server (this Flask application). Even though this application isn't directly authenticating users, the `python-keycloak` library often requires a `client_id` for initialization. 

    - `KEYCLOAK_CERT_PATH = "/app/certs/keycloak-cert.pem"`: The path to Keycloak's self-signed SSL certificate. 
    

4. **Initialize KeycloakOpenID Client:**

    - `keycloak_openid = KeycloakOpenID(...)`: This line initializes the `KeycloakOpenID` client.
        
        - `server_url`, `realm_name`, `client_id`: These are passed directly from the configuration.
            
        - `verify=KEYCLOAK_CERT_PATH`: Tells the client to verify Keycloak's SSL certificate using the provided path.
        

5. **Token Validation Decorator (`token_required`):**

    This is the core of the token validation logic. A decorator is a Python feature that allows you to wrap functions and modify their behavior.

    - `def token_required(func):`: Defines the decorator function, which takes another function (`func`, the route handler) as an argument.
        
    - `@functools.wraps(func)`: This is important for decorators. It preserves the original function's metadata (like its name and docstring), which is helpful for debugging and introspection.
        
    - `def decorated_function(*args, **kwargs):`: This is the inner function that will replace the original route handler.
        
        - `auth_header = request.headers.get('Authorization')`: Retrieves the `Authorization` header from the incoming HTTP request. This header is where JWTs are typically sent.
            
        - **Header Validation:**
            
            - `if not auth_header:`: Checks if the `Authorization` header is missing.
                
            - `parts = auth_header.split()`: Splits the header value (e.g., "Bearer" )
                
            - `if parts[0].lower() != 'bearer' or len(parts) != 2:`: Ensures the header starts with "Bearer" (case-insensitive) and has two parts.
                
            - If any of these checks fail, it returns a `401 Unauthorized` error with a descriptive message.
                
        - `token = parts[1]`: Extracts the actual JWT token from the header.
            
        - **Token Decoding and Validation:**
            
            - `try...except KeycloakInvalidTokenError...except Exception:`: This block handles potential errors during token validation.
                
            - `token_info = keycloak_openid.decode_token(token)`: This is the most important part. The `decode_token` method from the `python-keycloak` library does the following automatically:
                
                - **Signature Verification:** It fetches the public key from Keycloak's JWKS (JSON Web Key Set) endpoint for the specified realm and uses it to verify the token's cryptographic signature. This ensures the token hasn't been tampered with.
                    
                - **Expiration Check:** It verifies that the token's `exp` (expiration) claim is in the future.
                    
                - **Audience Check:** It verifies that the token's `aud` (audience) claim matches the `KEYCLOAK_AUDIENCE` configured for this resource server. If the token was not intended for "backend-service", it will be rejected. But as mentioned earlier, I couldn't get that part configured properly to work. 
                    
            - If `decode_token` is successful, it returns a dictionary (`token_info`) containing the decoded claims from the JWT.
                
            - If `KeycloakInvalidTokenError` occurs (e.g., signature mismatch, expired token, invalid audience), a `401 Unauthorized` error is returned.
                
            - A general `Exception` catches other potential issues during validation, returning a `500 Internal Server Error`.
                
        - `return func(token_info, *args, **kwargs)`: If the token is successfully validated, the original route handler (`func`) is called, and the `token_info` (decoded token claims) is passed as the first argument to it. This allows the protected endpoint to access information about the authenticated user or client.
        

6. **Protected API Route (`/api/data`):**

    - `@app.route("/api/data", methods=["GET"])`: Defines a Flask route for the `/api/data` endpoint, accessible via HTTP GET requests.
        
    - `@token_required`: This applies the `token_required` decorator to the `get_protected_data` function. This means that before `get_protected_data` is executed, the `token_required` decorator will first validate the incoming request's token.
        
    - `def get_protected_data(token_info):`: This is the actual route handler. It accepts `token_info` as an argument, which is provided by the `token_required` decorator after successful token validation.
        
        - `sample_data = {...}`: If the token is valid, this dictionary containing "protected" data is created.
            
        - `"authenticated_client": token_info.get('clientId'),`: Shows how to access claims from the decoded token (e.g., the `clientId` of the client that obtained the token).
            
        - `"token_audience": token_info.get('aud')`: Shows the `aud` claim from the token, confirming it matches the expected audience.
            
        - `return jsonify(sample_data)`: Returns the data as a JSON response with a `200 OK` status.
            

7. **Running the Flask App:**

    - `if __name__ == "__main__":`: This ensures the code inside this block only runs when the script is executed directly (not when imported as a module).
        
    - `app.run(host="0.0.0.0", port=8091, debug=True)`: Starts the Flask development server:
        
        - `host="0.0.0.0"`: Makes the server accessible from any IP address (useful for running in Docker containers or on a network).
            
        - `port=8091`: Specifies the port on which the server will listen.
            
        - `debug=True`: Enables Flask's debug mode, which provides helpful error messages and auto-reloading during development. **Important: Never use `debug=True` in a production environment.** I used it because I am just testing out these grant flows for learning purpose. 

