# Roles and Permissions with Keycloak

Authorization is more than just "who you are", it's about "what you can do". Keycloak provides robust mechanisms for managing roles and permissions.

## Realm Roles and Client Roles

### Realm Roles
These are roles defined at the realm level and are available to all clients within that realm. 

Examples: `admin, user, editor`

### Client Roles
These are roles specific to a particular client. They are often used to represent permissions within a specific application. 

Examples: 

Client : `my-web-app`

Roles : `view-data`, `edit-data`, `manage-users`

## Hands On Example
### Step 1: Setting up Client Roles with Keycloak CLI

1. **Getting Logged into the Keycloak CLI**

    ```bash
    # Logging In to the CLI
        /opt/keycloak/bin/kcadm.sh config credentials \
      --server https://keycloak:8443 \
      --realm master \
      --user $KEYCLOAK_ADMIN_USER \
      --password $KEYCLOAK_ADMIN_PASSWORD
    ```

2. **Getting the Client ID**

    ```bash
    # We need to get the Client ID
    # List clients in your realm and filter by clientId
    CLIENT_ID=$(/opt/keycloak/bin/kcadm.sh get clients -r my-app-realm -q clientId=my-web-app --fields id | grep id | cut -d ':' -f 2 | cut -d '"' -f 2)
    echo "Client ID for my-resource-api: $CLIENT_ID"
    ```

3. **Creating Client Roles**

    Let me create a few client roles.

    + view-profile
    + edit-profile
    + view-data
    + edit-data
    + manage-users
    + api-user
    + api-admin

    ```bash
    # Create a client role named 'view-profifle' for the 'my-web-app' client
    /opt/keycloak/bin/kcadm.sh create clients/$CLIENT_ID/roles \
        -r my-app-realm \
        -s name=view-profile \
        -s description='Role for API users with basic access'
    
    # Create a client role named 'edit-profifle' for the 'my-web-app' client
    /opt/keycloak/bin/kcadm.sh create clients/$CLIENT_ID/roles \
        -r my-app-realm \
        -s name=edit-profile \
        -s description='Role for API users with edit access'

    # Create a client role named 'view-data' for the 'my-web-app' client
    /opt/keycloak/bin/kcadm.sh create clients/$CLIENT_ID/roles \
        -r my-app-realm \
        -s name=view-data \
        -s description='Role for API users with view data access'

    # Create a client role named 'edit-data' for the 'my-web-app' client
    /opt/keycloak/bin/kcadm.sh create clients/$CLIENT_ID/roles \
        -r my-app-realm \
        -s name=edit-data \
        -s description='Role for API users with edit data access'

    # Create a client role named 'api-user' for the 'my-web-app' client
    /opt/keycloak/bin/kcadm.sh create clients/$CLIENT_ID/roles \
        -r my-app-realm \
        -s name=api-user \
        -s description='Role for API users with basic access'
    
    # Create a client role named 'api-admin' for the 'my-web-app' client
    /opt/keycloak/bin/kcadm.sh create clients/$CLIENT_ID/roles \
        -r my-app-realm \
        -s name=api-admin \
        -s description='Role for API users with admin access'

    # View the created client roles under the 'my-web-app' client
    /opt/keycloak/bin/kcadm.sh get clients/$CLIENT_ID/roles  -r my-app-realm
    ```

### Step 2: Creating users with Keycloak CLI

Let me create few users to I can allocate them to the roles which we created. 

+ anjelo
+ priyashan
+ dewni
+ hasitha
+ rajike

1. **Creating the Users**

    ```bash
    # Create user 'anjelo'
    /opt/keycloak/bin/kcadm.sh create users \
        --target-realm my-app-realm \
        --set username=anjelo \
        --set enabled=true \
        --set firstName="Anjelo" \
        --set lastName="Fernando" \
        --set email="anjelo@example.com"

    # Create user 'priyashan'
    /opt/keycloak/bin/kcadm.sh create users \
        --target-realm my-app-realm \
        --set username=priyashan \
        --set enabled=true \
        --set firstName="Priyashan" \
        --set lastName="Jayasankha" \
        --set email="priyashan@example.com"

    # Create user 'dewni'
    /opt/keycloak/bin/kcadm.sh create users \
        --target-realm my-app-realm \
        --set username=dewni \
        --set enabled=true \
        --set firstName="Dewni" \
        --set lastName="Fernando" \
        --set email="dewni@example.com"
    
    # Create user 'hasitha'
    /opt/keycloak/bin/kcadm.sh create users \
        --target-realm my-app-realm \
        --set username=hasitha \
        --set enabled=true \
        --set firstName="Hasitha" \
        --set lastName="Ranaweera" \
        --set email="Hasitha@example.com"
    
    # Create user 'rajike'
    /opt/keycloak/bin/kcadm.sh create users \
        --target-realm my-app-realm \
        --set username=rajike \
        --set enabled=true \
        --set firstName="Rajike" \
        --set lastName="Ekanayake" \
        --set email="rajike@example.com"

    ```

2. **Setting the Password for the Users**

    ```bash
    # Set password for 'anjelo'
    /opt/keycloak/bin/kcadm.sh set-password \
        --target-realm my-app-realm \
        --username anjelo \
        --new-password keycloak
        

    # Set password for 'rajike'
    /opt/keycloak/bin/kcadm.sh set-password \
        --target-realm my-app-realm \
        --username rajike \
        --new-password keycloak
        

    # Set password for 'priyashan'
    /opt/keycloak/bin/kcadm.sh set-password \
        --target-realm my-app-realm \
        --username priyashan \
        --new-password keycloak 
        

    # Set password for 'dewni'
    /opt/keycloak/bin/kcadm.sh set-password \
        --target-realm my-app-realm \
        --username dewni \
        --new-password keycloak 
        

    # Set password for 'hasitha'
    /opt/keycloak/bin/kcadm.sh set-password \
        --target-realm my-app-realm \
        --username hasitha \
        --new-password keycloak 
    ```

### Step 3: Assigning Roles to Users


1. **Assigning Roles**

    ```bash
    /opt/keycloak/bin/kcadm.sh add-roles \
        -r my-app-realm \
        --uusername "anjelo" \
        --cclientid my-web-app \
        --rolename "view-profile" 

    /opt/keycloak/bin/kcadm.sh add-roles \
        -r my-app-realm \
        --uusername "priyashan" \
        --cclientid my-web-app \
        --rolename "edit-profile" 
    
    /opt/keycloak/bin/kcadm.sh add-roles \
        -r my-app-realm \
        --uusername "dewni" \
        --cclientid my-web-app \
        --rolename "view-data" 

    /opt/keycloak/bin/kcadm.sh add-roles \
        -r my-app-realm \
        --uusername "hasitha" \
        --cclientid my-web-app \
        --rolename "api-user" 

    /opt/keycloak/bin/kcadm.sh add-roles \
        -r my-app-realm \
        --uusername "rajike" \
        --cclientid my-web-app \
        --rolename "api-admin" 

    ```

### Step4: Verifying Assignments

We can then check whether the users got the roles assigned. 

```bash
# We need to get the $USER_ID and $CLIENT_ID
/opt/keycloak/bin/kcadm.sh get users/$USER_ID/role-mappings/clients/$CLIENT_ID/composite -r my-app-realm
```

### Step 5: Removing Client Roles from Users

To remove a client role, we can use the `remove-roles` command. 

```bash
# Remove the 'api-admin' client role from 'testuser'
/opt/keycloak/bin/kcadm.sh remove-roles \
  -r my-app-realm \
  --uid $USER_ID \
  --cclientid my-resource-api \
  --rolename api-admin
```

## Implementing RBAC with Keycloak Client Roles using Python

Now, let me show an actual example where we use the client roles for authorization. I am going to extend the previous `web_app.py` and build the RBAC functionality on top of that. There fore the only part of the code which comes as new is below. 

```python
####################### ------------------ RBAC -------------- ##############################
from functools import wraps
from keycloak.exceptions import KeycloakInvalidTokenError

# Decorator to check for specific roles
def roles_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "token" not in session:
                return redirect(url_for("login"))

            try:
                # 1. Decode the Access Token, not the ID token.
                # The access token contains authorization details like roles.
                token_info = keycloak_openid.decode_token(
                    session["token"]["access_token"],
                    validate=True
                )

                # 2. Correctly extract client roles from the token.
                # The structure is: resource_access -> client_id -> roles (which is a list)
                resource_access = token_info.get("resource_access", {})
                client_access = resource_access.get(KEYCLOAK_CLIENT_ID, {})
                user_roles = client_access.get("roles", [])

                # 3. Check if the user has any of the required roles.
                if not any(role in user_roles for role in required_roles):
                    app.logger.warning(f"Access Denied for user {token_info.get('preferred_username')}. "
                                     f"Required: {required_roles}, User has: {user_roles}")
                    return "Access Denied: You do not have the required roles.", 403
            
            except KeycloakInvalidTokenError as e:
                app.logger.error(f"Invalid token: {e}")
                return "Access Denied: Your session is invalid or has expired. Please log in again.", 401
            except Exception as e:
                app.logger.error(f"Error checking roles: {e}")
                return "An error occurred while verifying your permissions.", 500
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route("/view_sensitive_data")
@roles_required("view-profile") # Only users with 'view-profile' role can access this route
def view_sensitive_data():
    return """
    <html>
        <body>
            <h2>Sensitive Data</h2>
                <p>This is highly confidential information that only authorized users can see.</p>
                <p><a href="/">Go Back Home</a></p>
        </body>
    </html>
    """

@app.route("/edit_user_data")
@roles_required("edit-profile") # Only users with 'edit-profile' role can access this route
def edit_user_data():
    return """
    <html>
        <body>
            <h2>Edit User Data</h2>
                <p>This page allows you to edit user data.</p>
                <p><a href="/">Go Back Home</a></p>
        </body>
    </html>
    """
################################# ------------------ RBAC END -------------- ##############################
```
### Code Break down (`web_app_with_rbac.py`)

**1. Imports:**

- `from functools import wraps`: This is used for creating decorators. `wraps` helps in preserving the original function's metadata (like `__name__`, `__doc__`) when a decorator is applied, which is useful for debugging and introspection.
    
- `from keycloak.exceptions import KeycloakInvalidTokenError`: This imports a specific exception from the Keycloak library, which will be caught if the access token is invalid.
    

**2. `roles_required` Decorator:**

This is the core of the RBAC implementation. It's a higher-order function that acts as a decorator.

- `def roles_required(*required_roles):`: This is the outer function of the decorator. It takes a variable number of arguments (`*required_roles`), which will be the roles required to access the decorated function (e.g., "view-profile", "edit-profile").
    
- `def decorator(f):`: This is the actual decorator function. It takes the function `f` (the view function, like `view_sensitive_data` or `edit_user_data`) that it will wrap.
    
- `@wraps(f)`: This applies the `wraps` decorator from `functools` to `decorated_function`. As mentioned, it helps preserve the metadata of the original function `f`.
    
- `def decorated_function(*args, **kwargs):`: This is the function that will replace the original `f` when the decorator is applied. It will contain the logic for role checking.
    
    - `if "token" not in session:`: This checks if an authentication token exists in the `session`. If not, it redirects the user to the login page. This assumes `session` is a global or context-bound object (common in Flask).
        
    - `try...except KeycloakInvalidTokenError...except Exception:`: This block handles potential errors during token processing.
        
        - **1. Decode the Access Token:**
            
            - `token_info = keycloak_openid.decode_token(session["token"]["access_token"], validate=True)`: This is a crucial step. It uses `keycloak_openid` (an assumed global or initialized Keycloak client instance) to decode the `access_token` from the user's session. The `validate=True` ensures that the token's signature, expiry, and other properties are checked. **It explicitly states to decode the Access Token, not the ID token, because the access token contains the authorization details (like roles).**
                
        - **2. Correctly extract client roles from the token:**
            
            - `resource_access = token_info.get("resource_access", {})`: Keycloak typically stores role information under the `resource_access` claim in the access token. This line safely retrieves it.
                
            - `client_access = resource_access.get(KEYCLOAK_CLIENT_ID, {})`: Within `resource_access`, roles are usually grouped by client ID. `KEYCLOAK_CLIENT_ID` is an assumed constant representing our application's client ID in Keycloak.
                
            - `user_roles = client_access.get("roles", [])`: Finally, this extracts the list of roles assigned to the user for our specific client.
                
        - **3. Check if the user has any of the required roles:**
            
            - `if not any(role in user_roles for role in required_roles):`: This line is the core authorization logic. It iterates through the `required_roles` (passed to the decorator) and checks if _any_ of them are present in the `user_roles` list. If _none_ of the required roles are found, access is denied.
                
            - `app.logger.warning(...)`: Logs a warning for auditing purposes when access is denied.
                
            - `return "Access Denied: You do not have the required roles.", 403`: Returns an "Access Denied" message with an HTTP 403 Forbidden status code.
                
        - **Error Handling:**
            
            - `except KeycloakInvalidTokenError as e:`: Catches specific Keycloak token errors (e.g., token expired, invalid signature). Returns a 401 Unauthorized status.
                
            - `except Exception as e:`: A general catch-all for any other unexpected errors during the process, returning a 500 Internal Server Error.
                
    - `return f(*args, **kwargs)`: If all role checks pass, the original function `f` (the view function) is called with its arguments and keyword arguments, and its return value is returned.
        

**3. Flask Routes with Decorator Usage:**

- `@app.route("/view_sensitive_data")`: This is a standard Flask route definition.
    
- `@roles_required("view-profile")`: This applies the `roles_required` decorator to the `view_sensitive_data`function. It specifies that only users with the "view-profile" role can access this route.
    
- `def view_sensitive_data():`: This is the Flask view function that serves sensitive data.
    
- `@app.route("/edit_user_data")`
    
- `@roles_required("edit-profile")`: Similarly, this route requires the "edit-profile" role.
    
- `def edit_user_data():`: This is the Flask view function for editing user data.
    






