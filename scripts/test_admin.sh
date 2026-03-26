#!/bin/bash

# Admin Dashboard Integration Test
# Usage: ./scripts/test_admin.sh <BASE_URL> <SUPER_ADMIN_TOKEN>

BASE_URL=${1:-"http://localhost:8080"}
TOKEN=$2

if [[ -z "$TOKEN" ]]; then
    echo "Usage: ./scripts/test_admin.sh <BASE_URL> <SUPER_ADMIN_TOKEN>"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "=== Admin Dashboard Test ==="

# 1. List Tenants
echo "Testing List Tenants..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/admin/tenants" \
    -H "Authorization: Bearer $TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" == "200" ]]; then
    echo -e "${GREEN}[PASS]${NC} List Tenants (HTTP 200)"
else
    echo -e "${RED}[FAIL]${NC} List Tenants (HTTP $HTTP_CODE)"
    echo "Response: $BODY"
fi

# 2. Update Tenant Status
echo "Testing Update Tenant Status..."
# Assuming tenant ID '1' or similar exists from seed
TENANT_ID=$(echo "$BODY" | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)

if [[ -z "$TENANT_ID" ]]; then
    echo "No tenant found to test status update. Skipping."
else
    RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH "$BASE_URL/admin/tenants/status?id=$TENANT_ID" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"is_active": false}')
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    if [[ "$HTTP_CODE" == "200" ]]; then
        echo -e "${GREEN}[PASS]${NC} Update Tenant Status (HTTP 200)"
    else
        echo -e "${RED}[FAIL]${NC} Update Tenant Status (HTTP $HTTP_CODE)"
    fi
fi

echo "============================"
