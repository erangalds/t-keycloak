from flask import Flask, redirect, request, session, url_for
from keycloak import KeycloakOpenID
import json 
import os 

# Initializes a Flask App object
app = Flask(__name__)
app.secret_key = os.urandom(24) # Used for Flask Session Management

# KeyCloak Configuration
KEYCLOAK_SERVER_URL = "https://keycloak:8443/"
KEYCLOAK_REALM = "my-app-realm"
KEYCLOAK_CLIENT_ID = "my-web-app"
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "vbw3lgpTtuVoq7Dl7VxKxzTzzJ4k3rjo") # Best practice: use env var

# Path to Keycloak's self-signed certificate inside the container
KEYCLOAK_CERT_PATH = "/app/certs/keycloak-cert.pem"

keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    realm_name=KEYCLOAK_REALM,
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret_key=KEYCLOAK_CLIENT_SECRET,
    verify=KEYCLOAK_CERT_PATH
)

@app.route("/")
def index():
    if "token" in session: 
        return f"""
        <html>
            <body>
                <h1>Welcome, {session.get('user_info',{}).get('preferred_username','User')}!</h1>
                    <p>Access Token: {session['token'].get('access_token')}</p>
                    <p><a href="/protected">Access Protected Resource</a></p>
                    <p><a href="/logout">Logout</a></p>
            </body>
        </html>
        """
    
    return """
            <html>
                <body>
                    <h1>Welcome to the Flask App!</h1>
                        <p><a href="/login">Login with Keycloak</a></p>
                </body>
            </html>
            """

@app.route("/login")
def login():
    # Generate a state value for CSRF protection and store it in the session
    state = os.urandom(24).hex()
    session['state'] = state

    # The method `auth_url`, which returns the authorization URL.
    auth_url = keycloak_openid.auth_url(
        redirect_uri=url_for("callback", _external=True),
        scope="openid profile email",
        state=state
    )

    return redirect(auth_url)

@app.route("/callback")
def callback():
    try:
        code = request.args.get("code")
        state = request.args.get("state")
        if not code:
            return "No authorization code provided", 400
        if not state or state != session.pop("state", None):
            return "Invalid state parameter.", 400

        # Exchange authorization code for tokens using the `token` method.
        token = keycloak_openid.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=url_for("callback", _external=True)
        )

        session["token"] = token

        # Get user info using the access token
        user_info = keycloak_openid.userinfo(token["access_token"])
        session["user_info"] = user_info

        return redirect(url_for("index"))
    
    except Exception as e:
        app.logger.error(f"Error during callback: {e}")
        return f"Error during callback: {e}", 500

@app.route("/protected")
def protected_resource():
    if "token" not in session:
        return redirect(url_for("login"))
    
    access_token = session["token"].get("access_token")

    return f"""
    <html>
        <body>
            <h2>Protected Resource</h2>
                <p>You have access because you authenticated successfully.</p>
                <p>Your ID Token Claims:
                {json.dumps(keycloak_openid.decode_token(session['token']['id_token']), indent=2)}
                <p><a href="/">Go Back Home</a></p>
        </body>
    </html>
    """

@app.route("/logout")
def logout():
    if "token" in session:
        keycloak_openid.logout(session["token"]["refresh_token"])
        session.pop("token", None)
        session.pop("user_info", None)
    return redirect(url_for("index"))

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
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=True)
    
