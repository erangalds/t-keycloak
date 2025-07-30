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