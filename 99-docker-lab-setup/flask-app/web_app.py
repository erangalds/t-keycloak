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

    # Example of accessing a hypothetical protected resource
    # In a real scenarios, this would be an API call to your Resource Server
    # that validates the access_token
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=True)



    
