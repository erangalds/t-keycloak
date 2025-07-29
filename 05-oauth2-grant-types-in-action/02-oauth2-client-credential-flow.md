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
    
    