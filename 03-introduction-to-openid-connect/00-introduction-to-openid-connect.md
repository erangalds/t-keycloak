# Introduction to OpenID Connect (OIDC) 

## OIDC vs OAuth2 🆚

While OAuth2 is an **authorization framework**, OpenID Connect (OIDC) is an **identity layer built on top of OAuth2**.

- **OAuth2**: Focuses on _authorization_ – allowing an application to access _resources_ on behalf of a user. It answers the question: "Can this application access my photos?"
    
- **OIDC**: Focuses on _authentication_ – verifying the identity of the user and providing basic profile information. It answers the question: "Who is the user currently using this application?"

## ID Tokens and UserInfo Endpoint 🆔

- **ID Token**: A **JWT (JSON Web Token)** issued by the Authorization Server that contains claims (information) about the authenticated user, such as their name, email, and user ID. This token is primarily for the client to verify the user's identity.
    
- **UserInfo Endpoint**: A protected resource endpoint on the Authorization Server that returns additional claims about the authenticated user. Clients can access this endpoint using the access token.

When you use **Keycloak** for authentication, you'll often be using OIDC, as it provides both authentication and authorization capabilities. It handles the complex OAuth2 and OIDC protocol details, allowing our application to focus on their core business logic.  

Let's look at comple of examples: 

## Scenario 1: Logging into a Third-Party Application with Keycloak (Web Application) 🌐

### The Goal:

A user wants to sign in to an **online recipe sharing website (the Client Application)**. Instead of "Login with Google," they now use **"Login with My Company Account"**, where "My Company Account" is managed by **Keycloak**. After signing in, the recipe website also wants to allow the user to **import recipes from a backend service protected by Keycloak**, on behalf of the user.

### Keycloak's Role:

Keycloak acts as the **Authorization Server** and **OpenID Provider (IdP)**. It manages user accounts, authenticates users, issues ID Tokens (for identity) and Access Tokens (for authorization), and supports the various OAuth2 and OIDC flows.

### How it Works with Keycloak:

1. **Keycloak Setup (Admin):**
    
    - An administrator configures a **Realm** in Keycloak (e.g., `my-company-realm`).
        
    - They create a **Client** in this realm for the "Recipe Sharing Website" (e.g., `recipe-app`), configuring it as an **OpenID Connect** client with the "Standard Flow" (Authorization Code) enabled, and specifying its `redirect_uri`. This client will have a `client_id` and a `client_secret`.
        
    - They define **Scopes** for any resources the recipe app might need to access (e.g., a custom scope `recipe_import` for the backend recipe service).
        
    - Users are created and managed within this Keycloak Realm.
        
2. **Authentication (OIDC) via Keycloak:**
    
    - **User Action:** The user visits the recipe sharing website and clicks "Login with My Company Account."
        
    - **Authorization Request (OAuth2 + OIDC):** The recipe website redirects the user's browser to **Keycloak's Authorization Endpoint** (e.g., `https://keycloak.mycompany.com/realms/my-company-realm/protocol/openid-connect/auth`). This request includes:
        
        - `client_id=recipe-app`
            
        - `redirect_uri=https://recipe.mycompany.com/callback`
            
        - `response_type=code`
            
        - `scope=openid profile email recipe_import` (OIDC scopes + custom OAuth2 scope).
            
        - `nonce` (OIDC-specific).
            
    - **User Interaction (Keycloak Login & Consent):** The user is presented with **Keycloak's login page**. After logging in, Keycloak displays a consent screen asking the user to authorize the `recipe-app` to access their profile, email, and to `recipe_import`.
        
    - **Authorization Code & ID Token (via redirect):** If consent is granted, Keycloak redirects the user's browser back to `https://recipe.mycompany.com/callback` with an `authorization_code` and an **`id_token`** (JWT).
        
    - **Token Exchange (Back-channel):** The recipe website's backend server uses the `authorization_code` and its `client_secret` to make a secure POST request to **Keycloak's Token Endpoint** (e.g., `https://keycloak.mycompany.com/realms/my-company-realm/protocol/openid-connect/token`). Keycloak validates these and returns an `access_token` (OAuth2) and a new, typically more robust, **`id_token`** (OIDC), and a `refresh_token`.
        
    - **Identity Verification:** The recipe website's backend **validates the `id_token`'s signature** using Keycloak's public keys (obtained from Keycloak's JWKS endpoint). It then extracts the user's identity claims (e.g., `sub`, `name`, `email`) from the `id_token` to authenticate the user and create a session.
        
3. **Authorization (OAuth2) for Resource Access:**
    
    - **Resource Access:** When the user wants to import recipes, the recipe website's backend uses the **`access_token`** to make API calls to the **backend recipe service (Resource Server)**.
        
    - **Keycloak's Role (Resource Server side):** The backend recipe service is also configured in Keycloak (often as another client or an API resource). It uses Keycloak's client libraries or standard JWT validation logic to:
        
        - **Validate the `access_token`:** It verifies the token's signature (using Keycloak's public keys), issuer, audience (which is its own client ID or API resource ID in Keycloak), and expiration.
            
        - **Check Scopes/Roles:** It ensures the `access_token` contains the `recipe_import` scope (or a role mapped to it in Keycloak) before allowing the operation.
            
    - **UserInfo Endpoint (Optional OIDC):** If the recipe app needs more user profile details than what's in the `id_token` (or dynamic data), it can use the `access_token` to call **Keycloak's UserInfo Endpoint** (e.g., `https://keycloak.mycompany.com/realms/my-company-realm/protocol/openid-connect/userinfo`), which returns additional user attributes.
        

In this flow, **Keycloak is the central identity provider**, handling the login experience and issuing tokens that assert both the user's identity (ID Token) and the application's permission to act on their behalf (Access Token).

---

## Scenario 2: Mobile Application Accessing Protected API and User Profile via Keycloak 📱

### The Goal:

A **mobile fitness tracker application (the Client Application)** wants its users to sign in using their **My Company Account (managed by Keycloak)**. After signing in, the app needs to:

1. Display the user's **first name and profile picture**.
    
2. Allow the app to **upload workout data** to the user's account on a **backend fitness API (the Resource Server)**.
    

### Keycloak's Role:

Again, Keycloak serves as the **Authorization Server** and **OpenID Provider (IdP)**, but this time specifically supporting the **Authorization Code Flow with PKCE**, which is crucial for public clients like mobile apps.

### How it Works with Keycloak:

1. **Keycloak Setup (Admin):**
    
    - An administrator configures a **Realm** in Keycloak.
        
    - They create a **Client** for the "Mobile Fitness App" (e.g., `fitness-mobile-app`), configuring it as an **OpenID Connect** client.
        
    - Crucially, for a mobile app, the "Access Type" might be set to **"public"** and **PKCE** support is enabled by default for the standard flow. You'll specify its `redirect_uri` (e.g., a custom URI scheme like `myapp://callback` or a Loopback IP).
        
    - They define **Scopes** for the backend fitness API (e.g., `workout_upload`).
        
    - Users are provisioned in this Keycloak Realm.
        
2. **Authentication (OIDC) & Initial Authorization (OAuth2) via Keycloak with PKCE:**
    
    - **User Action:** The user opens the mobile fitness app and taps "Sign In."
        
    - **Generate PKCE Secrets:** The mobile app dynamically generates a `code_verifier` (a cryptographically random string) and then calculates its `code_challenge`. The `code_verifier` is stored locally in memory or secure storage.
        
    - **Authorization Request (OAuth2 + OIDC with PKCE):** The mobile app redirects the user to **Keycloak's Authorization Endpoint**. This request includes:
        
        - `client_id=fitness-mobile-app`
            
        - `redirect_uri=myapp://callback`
            
        - `response_type=code`
            
        - `code_challenge` and `code_challenge_method=S256`
            
        - `scope=openid profile workout_upload`
            
        - `nonce`
            
    - **User Interaction (Keycloak Login & Consent):** The user is presented with **Keycloak's themed login page**. After logging in, Keycloak displays a consent screen for the `fitness-mobile-app` to access their profile and `workout_upload`.
        
    - **Authorization Code & ID Token (via redirect):** If consent is granted, Keycloak redirects the user's browser (or a custom tab) back to the mobile app's `redirect_uri` with an `authorization_code` and an **`id_token`**.
        
    - **Token Exchange (Back-channel):** The mobile app then makes a direct POST request to **Keycloak's Token Endpoint**, sending the `authorization_code`, its `client_id`, and the original `code_verifier`. Keycloak validates the `code_verifier` against the `code_challenge` it received earlier. If valid, it returns an `access_token` (OAuth2), a new **`id_token`** (OIDC), and a `refresh_token`.
        
    - **Identity & Profile Information:** The mobile app **validates the `id_token`** locally. It extracts `given_name` and `picture` from the `id_token`'s claims to display "Welcome, [User's First Name]!"
        
3. **Authorization (OAuth2) for Resource Access:**
    
    - **Resource Access:** When the user completes a workout and the app needs to upload data, the mobile app uses the **`access_token`** to make an authenticated request to the **backend fitness API (Resource Server)**.
        
    - **Keycloak's Role (Resource Server side):** The backend fitness API is also configured in Keycloak (as a client or resource). It uses Keycloak's libraries or standard JWT validation to:
        
        - **Validate the `access_token`:** It verifies the token's signature (using Keycloak's public keys), issuer, audience, and expiration.
            
        - **Check Scopes/Roles:** It ensures the `access_token` contains the `workout_upload` scope (or a role mapped to it in Keycloak) before processing the workout data upload.
            
    - **UserInfo Endpoint (for richer, dynamic profile data):** If needed, the app can call **Keycloak's UserInfo Endpoint** with the `access_token` to retrieve more extensive or up-to-date user profile attributes beyond what's in the `id_token`.
        

In both these scenarios, **Keycloak is the central identity authority.** It provides the secure infrastructure for user authentication (via OIDC) and then issues tokens that grant applications specific permissions (via OAuth2) to access other protected resources, all while abstracting away the complex security protocols from your application logic.
