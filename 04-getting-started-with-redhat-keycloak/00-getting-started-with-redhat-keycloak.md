# Getting Started with Red Hat KeyCloak

## What is KeyCloak? 🗝️

RedHat KeyCloak is an open-source Identity and Access Management (IAM) solution that enables you to seecure application and services with minimal effort. It supports standard products like OAuth2, OpenID Connect, and SAML. KeyCloak provides: 

+ **Single-Sign-On (SSO)**: Users log in once and gain access to multiple applications

+ **Centralized User Management**: Manage users, roles, and groups in one place. 

+ **Social Login**: Integrate with social identity providers like Google, GitHub etc. 

+ **Multi-Factor Authentication (MFA)**: Enhance security with additional authentication. 

+ **Authorizatopm Services**: Implement fine-grained authorizaiton policies. 

## Installation and Setup 🛠️

We need a working **Keycloak** setup to learn about Keycloak with hands-on exercises. Therefore, I am going to show you how to setup a practice lab environment with Docker Containers. 

First let us download the docker image for *Keycloak*. 

**Step 1**: 

```bash
# Downloading Docker image
docker pull quay.io/keycloak/keycloak:latest
```

**Step 2**:

Now, let us create a container instance. Using the below command I can easily get a keycloak container instance to run. 

```bash
# Using docker container run 
docker container run -d -p 8080:8080 \
-e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
-e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
--name keycloak quay.io/keycloak/keycloak:latest \
start-dev 
```

But this is the best possible way to setup a keycloak setup. Because in the above case, the all the *Keycloak* configurations like `realms, users, groups` etc gets stored in an in memory database. There is change that we might loose that information is something happens to the container instanace. Therefore, it would be better to have a setup where we can persist the configuration and settings. 

When I looked at how *Keycloak* persist the data, what I found was that it uses a *Postgres* Database to save all the critical information like configurations and settings. The other customizations like, `themes` and `providers` gets saved on the filesystem. Also to keep the self-signed certificates we need another folder. Therefore I need to create another folder named `certs` in the same project root folder. Therefore considering all of these needs let me show you how to setup the proper way to setup the container instance using the `docker-compose.yml` file. 

```yaml

services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    container_name: keycloak
    volumes:
      # Mount your themes, providers, and certificates directories
      - ./themes:/opt/keycloak/themes/  # No change, but included for context
      # Mount a local directory for custom providers (.jar files).
      - ./providers:/opt/keycloak/providers/  # No change, but included for context
      - ./certs:/opt/keycloak/certs:ro  # Mount certs directory as read-only
    command:
      - start
      - "--db=postgres"
      - "--db-url-host=keycloak-postgres"
      - "--db-url-database=${POSTGRES_DB}"
      - "--db-username=${POSTGRES_USER}"
      - "--db-password=${POSTGRES_PASSWORD}"
      - "--https-key-store-file=/opt/keycloak/certs/keystore.jks"  # Added parameter for HTTPS

    environment:
      # Keycloak Admin Credentials
      KC_BOOTSTRAP_ADMIN_USERNAME: ${KEYCLOAK_ADMIN_USER}
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}

      # Database Configuration
      KC_DB: postgres
      KC_DB_URL_HOST: keycloak-postgres
      KC_DB_URL_DATABASE: ${POSTGRES_DB}
      KC_DB_USERNAME: ${POSTGRES_USER}
      KC_DB_PASSWORD: ${POSTGRES_PASSWORD}
      KC_DB_SCHEMA: public

      # Set the hostname for production-like behavior
      KC_HOSTNAME: localhost # No change, but included for context

      # Enable HTTPS and set key store parameters
      # KC_HTTPS_CERTIFICATE_FILE: /opt/keycloak/certs/keystore.jks  # Removed as it's passed in command
      # KC_HTTPS_CERTIFICATE_KEY_FILE: /opt/keycloak/certs/keystore.jks  # Removed as it's passed in command
      KC_HTTPS_PORT: 8443
      KC_HTTPS_CLIENT_AUTH: none  # Disable client authentication
      KC_HTTP_ENABLED: false # Disable the HTTP endpoint
      KC_HOSTNAME_STRICT: false
      KC_HOSTNAME_STRICT_HTTPS: false
    ports:
      - "8443:8443"
      - "8080:8080" # Keep 8080 open for http redirects and reverse proxies to use
    depends_on:
      keycloak-postgres:
        condition: service_healthy
    networks:
      - keycloak_net
    restart: unless-stopped



  keycloak-postgres:
    image: postgres:17 # Use a stable and valid postgres version
    container_name: keycloak-postgres 
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    healthcheck: # Check if the database is ready to accept connections
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - keycloak_net
    restart: unless-stopped

networks: 
  keycloak_net:
volumes:
  postgres_data:
```

Here you can see what we sensitive information like, `usernames`, `passwords` I have moved to a `.env` file which is in the same folder. Below is how it looks like. 

```bash
# Keycloak Admin User
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=change_me

# PostgreSQL Database connection settings
POSTGRES_DB=postgres
POSTGRES_USER=keycloak
POSTGRES_PASSWORD=change_me
```
Before starting the things we need to generate self-signed certificates. To enable HTTPS communication on the Keycloak. I was able to get that done using `openssl` utility. 

```bash
openssl req -x509 -out server.crt -keyout server.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\n")
```

Now I need to pacakge these into a *Java Keystore (`.jks`) file. Let me do what with the help of `keytool` utility. 

```bash
keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=localhost" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore keycloak.p12
keytool -importkeystore -srckeystore keycloak.p12 -srcstorepass password -srcstoretype pkcs12 -destkeystore keystore.jks -deststorepass password
```


Right, then let's create the container instances. 

```bash
# Creating the docker containers and starting them. 
docker-compose up -d
# Validate 
docker container ps
```

Now let us go to the url [localhost:8443](http://localhost:8443) and see. Finally, I should be able to log in. 

Below is the home page of the admin. 

![Admin Home](./images/admin_home.png)

## Keycloak Realms, Clients and Users

Now that we have a



