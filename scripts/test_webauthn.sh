#!/bin/bash

# WebAuthn Integration Test (Accessibility Check)
# Usage: ./scripts/test_webauthn.sh <BASE_URL> <USER_EMAIL> <ACCESS_TOKEN>

BASE_URL=${1:-"http://localhost:8080"}
EMAIL=$2
TOKEN=$3

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "=== WebAuthn Endpoint Test ==="

# 1. Begin Login (Public)
echo "Testing Begin Login..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/webauthn/login/begin" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

# Status 401/404 is expected if user doesn't have WebAuthn enabled
if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "401" || "$HTTP_CODE" == "404" ]]; then
    echo -e "${GREEN}[PASS]${NC} Begin Login accessible (HTTP $HTTP_CODE)"
else
    echo -e "${RED}[FAIL]${NC} Begin Login failed (HTTP $HTTP_CODE)"
fi

# 2. Begin Registration (Protected)
if [[ -n "$TOKEN" ]]; then
    echo "Testing Begin Registration..."
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/webauthn/register/begin" \
        -H "Authorization: Bearer $TOKEN")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    if [[ "$HTTP_CODE" == "200" ]]; then
        echo -e "${GREEN}[PASS]${NC} Begin Registration (HTTP 200)"
    else
        echo -e "${RED}[FAIL]${NC} Begin Registration failed (HTTP $HTTP_CODE)"
    fi
fi

echo "=============================="
