# Introduction to OAuth2

## The Problem OAuth2 Solves 💡

Imagine you want to use a photo printing service that needs access to your photos stored on Google Photos. Without OAuth2, you'd have to give the photo printing service your Google Photos username and password. This is a huge security risk! If the printing service's database is compromised, your Google Photos credentials are stolen.

OAuth2 solves this by allowing you to grant the photo printing service **limited access** to your Google Photos, specifically just for retrieving photos, without ever sharing your Google password with them.

## Key Role in OAuth2  🎭

OAuth has predifined four main roles: 

+ **Resource Owner**: This is the user who own the protected resources (e.g. your photos, your profile data, your bank account information). You are the resource owner when you want to authorize an application to access your data. 

+ **Client(Application)**: This is the application (e.g. the photo printing service, a mobile app, a web application) that wants to access the protected resources on behalf of the resource owner. 

+ **Authorization Server**: This is the server that handles the *authentication* of the *resource owner* and issues *access tokens** to the *client*. In this traning module ***KeyCloak*** is the *authorization server*. 

+ **Resource Server**: This is the serrver that hosts the protected resources and can accept and respond to protected resource requests using access tokens. This would be. your API or service that needs to be protected. 

## OAuth2 Grant Types (Flows) 🌊

Grant types (or flows) are the methods a client uses to obtain an access token. OAuth2 provides several grant types for different scenarios.

1. **Authorization Code Flow**:  
    This is the most common and recommended flow for confidential clients (applications that can securely store a client secret, like server side web applications). It involves an authorization code exchange for an access token. 

    + **How it Works**.   
    This flow is a multi-step process designed for security. Instead of directly giving the client an access token, the authorization server first issues a temporary "authorization code." This code is then securely exchanged by the client's backend (where its client secret can be protected) for the actual access token. This prevents the access token from being exposed in the user's browser or logs.

    - **When to Use**.    
        + Traditional web applications (server-side rendered)

        + Single-page applications (SPAs) when combined with **PKCE (Proof Key for Code Exchange)**

        + Mobile and Desktop applications when combined with **PKCE**

    - **Example**
        
        Imagine you are building a web application (e.g. "My Photo Editor") that allows users to import photos from their Google Photos account. Below is the process flow. 

        1. **User Initiates**: On "My Photo Editor", the user clicks an "Import from Google Photos" button 

        2. **Redirect to Google**: "My Photo Editor" redirects the user's browser to Google's authorization server (e.g. accounts.google.com). The URL includes parameters like `client_id, redirect_uri`, and `scope` (e.g. `photos.readonly`)

        3. **User consent**: Google's Authorization Server prompts the user to log into their Google Account (if not already logged in) and then asks for their consent to allow "My Photo Editor" to access their Google Photos. 

        4. **Authorization Code Issued**: If the user grants consent, Google's Authorization Server redirects the user's browser back to "My Photo Editor" app's pre-registered `redirect_uri`. This redirect URL now includes a temporary *authorization code* (e.g., `myphotoeditor.com/callback?code= SplendidAuthCode123`).

        5. **Code Exchange (Server-Side)**: "My Photo Editor" app's backend server receives this authorization code. It them immediately make a direct, secure **POST** request to Google's Token Endpoint, sending the `authorization_code`, its `client_id` and its `client_secret`. 

        6. **Access Token Issued**: Google's Token Endpoint validates the code and the client secret. If valid, it issues an **access token** (and often a refresh token) to "My Photo Editor's" backend server.

        7. **Resource Access**: "My Photo Editor" now uses this access token to make API calls to Google Photos (the Resource Server) on behalf of the user to retrieve their photos. The access token is stored securely on the backend and never exposed to the user's browser. 

    
2. **Client Credentials Flow**: 

    Used for **machine-to-machine communication**, where an application accesses its own resources or resources for which it has been *pre-authorized*, without user's involvement. 

    + **How it Works**.

        This flow is for when an application itself is the "resource owner" or needs to act on its own behalf, not on behalf of a specific end-user. There's no user interface or user interaction involved. The client authenticates directly with the authorization server using its `client_id` and `client_secret` to obtain an access token.

    - **When to Use**.

        + Backend services communicating with other APIs (e.g. a microservice calling another internal service)

        + Batch jobs or automated scripts accessing an API.

        + CLI tools performing administrative tasks. 

    + **Examples**

        Consider an internal "Inventory Management Service" that needs to update stock levels in a "Warehouse API" provided by another internal team. No end-user is directly interacting with this process. Below is how the process works. 

        1. **Service Request:** The "Inventory Management Service" needs to update stock for a product.

        2. **Token Request:** The "Inventory Management Service" makes a direct **POST request** to the Authorization Server's Token Endpoint, providing its `client_id` and `client_secret`, and specifying `grant_type=client_credentials`.    

        3. **Access Token Issued:** The Authorization Server authenticates the "Inventory Management Service" using its credentials. If valid, it issues an **access token** directly to the "Inventory Management Service."
        
        4. **Resource Access:** The "Inventory Management Service" then uses this access token to call the "Warehouse API" (Resource Server) to update the stock. The Warehouse API validates the token and, if authorized, processes the stock update.

3. **Implicit Grant Flow**:

    (Deprecated in OAuth 2.1) Was previously used for browser-based applications, but is now largely replaced by the Authorization Code Flow with PKCE for better security. The access token was returned directly.

    + **How it Works**.

        This flow was designed for public clients (like SPAs) that couldn't securely store a client secret. The access token was returned directly in the URL fragment after the user's consent, avoiding a server-side exchange. However, this exposed the access token to potential risks (e.g., URL leaks, browser history, malicious scripts).

    + **When it was Used (and Why It's Deprecated)**:

        + Single Page Applications (SPAs).

        + Mobile and Desktop Applications. 

        + **Deprecated** due to security vulnerabilities, especially related to token leakage and lack of authorization code binding. 


    +  **Example**

        Imagine an older version of a browser-based "Photo Gallery" application.

        1. **User initiates:** User clicks "Connect to Cloud Storage."

        2. **Redirect to Auth Server:** The "Photo Gallery" redirects the user to the Cloud Storage Authorization Server.    

        3. **User Consent:** User logs in and grants permission.
        
        4. **Direct Token Return (Vulnerable):** The Authorization Server redirects the user's browser back to the "Photo Gallery" with the **access token directly in the URL fragment** (e.g., `photogallery.com/#access_token=SuperSecretToken`).
        
        5. **Resource Access:** The "Photo Gallery" (JavaScript in the browser) extracts the access token and uses it to call the Cloud Storage API.

        The problem here is that the access token is directly exposed in the browser's URL, making it vulnerable to interception by malicious scripts or being logged.

4.  **Resource Owner Password Credentials Flow**:

    (Generally discouraged) The client directly asks for the user's username and password and then sends them to the authorization server to get an access token. Only for highly trusted applications where other flows are not feasible.

    + **How it Works**.

        In this flow, the client application collects the user's username and password (the "resource owner's credentials") and sends them directly to the authorization server's token endpoint. The authorization server authenticates the user and, if valid, issues an access token.

    +  **When to Use**.

        + **Only for highly trusted applications**.

        + Legacy systems where refactoring to other flows impossible. 

        + **Almost never for third-party applications**. It bypasses the user consent screen and gives teh application direct access to user credentials, which is a significant security risk. It also typically doesn't support Multi Factor Authentication (MFA)

    +  **Example**

        A legacy, tightly integrated mobile banking application developed by the bank itself, where the user might enter their credentials directly into the app.

        1. User Input: The user opens the "My Bank" mobile app and enters their username and password directly into the app's login screen. 

        2. **Direct Credential Exchange**: The "My Bank" app (the client) makes a POST request to teh bank's Authorization Server, sending the `username`, and `password`, its own `client_id`, and `client_secret` (if applicable), specifying the `grant_type=password`

        3. **Access Token Issued**: the Authorization Server authenticates the user using the provided credentials. If valid, it issues an access token to the "My Bank" app. 

        4. **Resource Accees**: The "My Bank" app uses this access token to access the user's banking information via Bank's APIs. 

        This flow is problematic because the client application handles sensitive user credentials, which significantly increases the risk of credential compromise if the app's security is breached.


5. **Proof Key for Code Exchange (PKCE)**

    An extension to the Authorization Code Flow, primarily for public clients (like mobile or single-page applications) that cannot securely store a client secret. It prevents authorization code interception attacks.

    + **How it Works**.

        PKCE (pronounced "pixy") adds an extra layer of security to the Authorization Code Flow, specifically for public clients. It prevents an attacker who intercepts the authorization code from exchanging it for an access token. It does this by introducing a dynamically generated "code verifier" and a "code challenge" during the authorization request. The client must present the `code_verifier` when exchanging the authorization code for a token, which the authorization server verifies against the `code_challenge` it received earlier.

    + **When to Use**.

        + **Single-page applications (SPAs)**, which run run entirely in the browser and cannot securely store a client secret. 

        + **Native mobile application**

        + **Desktop application**

        + Highly recommended for ALL **Authorization Code Flow** implementations, even confidentials clients, as its adds robust protection against various attacks vectors. 

    + **Example**


        Let's revisit the "My Photo Editor" example, but now as a Single-Page Application (SPA) running purely in the browser, using PKCE.

        1. **Generate Code Verifier & Challenge:** "My Photo Editor" (JavaScript in the browser) first generates a cryptographically random `code_verifier` (e.g., `RAnDomStRinG123`). It then hashes this `code_verifier`using SHA256 and Base64Url-encodes it to create a `code_challenge` (e.g., `xY7Z_AbCdEf...`). The `code_verifier` is stored temporarily in the browser's session storage.

        2. **User initiates & Redirect with Challenge:** The user clicks "Import from Google Photos." "My Photo Editor" redirects the user's browser to Google's Authorization Server, including `client_id`, `redirect_uri`, `scope`, and the `code_challenge` and `code_challenge_method=S256`.

        3. **User Consent:** Google's Authorization Server prompts the user for login and consent.

        4. **Authorization Code Issued:** If consented, Google redirects the browser back to "My Photo Editor"'s `redirect_uri` with the `authorization_code`.

        5. **Code Exchange with Verifier:** "My Photo Editor"'s JavaScript now makes a **direct POST request** to Google's Token Endpoint (from the browser), sending the `authorization_code`, its `client_id`, AND the original `code_verifier`.    
        
        6. **Verification and Token Issued:** Google's Token Endpoint receives the `code_verifier`. It independently computes the `code_challenge` from this `code_verifier` using the specified method (S256) and compares it to the `code_challenge` it received in step 2. If they match, it validates the authorization code and issues an **access token** (and refresh token) directly to "My Photo Editor" (in the browser).
        
        7. **Resource Access:** "My Photo Editor" uses this access token to call the Google Photos API.
    

        The key here is that even if an attacker intercepts the `authorization_code` in step 4, they won't have the `code_verifier` stored securely by the legitimate client, and therefore cannot exchange the code for an access token in step 5. This makes PKCE essential for public clients.


## Access Tokens and Refresh Tokens 🔑

Let's clarify the difference between these two types: 

+ **Access Token**: A credential that represents the authorization granted by the resource owner to the client. It's typically a **short-lived, opaque string or a JWT (JSON Web Token) that the client includes in requests to the resource server. The resource server validates this token to grant access. 

+ **Refresh Token**: A credential used to obtain new access tokens when the current access token expires, without requiring the user to re-authenticate. Refresh tokens are typically **long-lived** and should be stored securely. 

## Scopes

**Scopes** define the **permissions** that an access token grants. They specify the limited access a client has to a resource owner's data. For example, a scope could be `read:email`, `write:profile`, or `access:photos`. The resource owner usually sees these scopes and has to consent to them during the authorization process.




        

    