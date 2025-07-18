#!/bin/bash

KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=keycloak

docker compose run --rm kcadm config credentials \
    --server https://keycloak:8443 \
    --realm master \
    --user "${KEYCLOAK_ADMIN_USER}" \
    --password "${KEYCLOAK_ADMIN_PASSWORD}" \
    --config /home/keycloak/.keycloak/kcadm.config

