#!/bin/bash

# Configuration
BASE_URL=${1:-"http://localhost:8080"}

# Generate random user data to avoid conflicts for idempotency
TIMESTAMP=$(date +%s)
EMAIL="test_${TIMESTAMP}@example.com"
USERNAME="testuser_${TIMESTAMP}"
PASSWORD="Password123!"

WRONG_PASSWORD="WrongPassword1!"
BAD_EMAIL="not-an-email"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

echo -e "${CYAN}=== Script Integrasi Test (E2E & Partial Failures) ===${NC}"
echo -e "Target URL: $BASE_URL"
echo -e "Session ID/Unique User: $EMAIL"
echo -e "========================================================\n"

check_response() {
    local feature=$1
    local http_code=$2
    local expected_code=$3
    local response_body=$4

    if [[ "$expected_code" == *"$http_code"* ]]; then
        echo -e "${GREEN}[PASS]${NC} $feature (HTTP $http_code)"
    else
        echo -e "${RED}[FAIL]${NC} $feature"
        echo -e "       Expected HTTP $expected_code, got $http_code"
        echo -e "       Response: $response_body"
    fi
}

echo -e "${MAGENTA}--- 1. NEGATIVE TESTS: Register ---${NC}"

# A. Register without email (Validation Error)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"username": "test", "password": "Password123!"}')
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Register Without Email (Validation)" "$HTTP_CODE" "400" "$BODY"

# B. Register with invalid email format (Validation Error)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"username": "test", "email": "invalidemail", "password": "Password123!"}')
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Register Invalid Email Format (Validation)" "$HTTP_CODE" "400" "$BODY"

echo -e "\n${MAGENTA}--- 2. POSITIVE TESTS: Register & Auth ---${NC}"

# C. Normal Register
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "'"$USERNAME"'",
        "email": "'"$EMAIL"'",
        "password": "'"$PASSWORD"'"
    }')
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Normal Register" "$HTTP_CODE" "201" "$BODY"

# D. Register with duplicate email (Conflict)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "'"$USERNAME"'",
        "email": "'"$EMAIL"'",
        "password": "'"$PASSWORD"'"
    }')
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
# Some APIs return 409 Conflict, some return 400 Bad Request
check_response "Register Duplicate Email (Conflict)" "$HTTP_CODE" "400|409" "$BODY"


echo -e "\n${MAGENTA}--- 3. NEGATIVE TESTS: Login ---${NC}"

# E. Login with non-existent email
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "nobody@example.com", "password": "Password123!"}')
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Login Non-Existent User" "$HTTP_CODE" "401|404|400" "$BODY"

# F. Login with wrong password
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'"$EMAIL"'",
        "password": "'"$WRONG_PASSWORD"'"
    }')
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Login Wrong Password" "$HTTP_CODE" "401|400" "$BODY"


echo -e "\n${MAGENTA}--- 4. POSITIVE TESTS: Login & Tokens ---${NC}"

# G. Normal Login
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'"$EMAIL"'",
        "password": "'"$PASSWORD"'"
    }')
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Normal Login" "$HTTP_CODE" "200" "$BODY"

ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
REFRESH_TOKEN=$(echo "$BODY" | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)


echo -e "\n${MAGENTA}--- 5. MIDDLEWARE / AUTHORIZATION TESTS ---${NC}"

# H. Access Protected Route Without Token
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Access /me Without Token" "$HTTP_CODE" "401" "$BODY"

# I. Access Protected Route With Bad Token
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer my-invalid-token")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Access /me With Invalid Token" "$HTTP_CODE" "401" "$BODY"

# J. Access Protected Route Successfully
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Access /me With Valid Token" "$HTTP_CODE" "200" "$BODY"


echo -e "\n${MAGENTA}--- 6. REFRESH TOKEN TESTS ---${NC}"

# K. Invalid Refresh Token
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/token/refresh" \
    -H "Authorization: Bearer bad-refresh-token")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Refresh With Invalid Token" "$HTTP_CODE" "401" "$BODY"

# L. Valid Refresh Token
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/token/refresh" \
    -H "Authorization: Bearer $REFRESH_TOKEN")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Valid Refresh Token" "$HTTP_CODE" "200" "$BODY"

NEW_ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
if [ -n "$NEW_ACCESS_TOKEN" ]; then
    ACCESS_TOKEN=$NEW_ACCESS_TOKEN
fi


echo -e "\n${MAGENTA}--- 7. MFA TESTS ---${NC}"

# M. MFA Setup
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/mfa/setup" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "MFA Setup (Get Secret)" "$HTTP_CODE" "200|201" "$BODY"


echo -e "\n${MAGENTA}--- 8. LOGOUT & INVALIDATION TESTS ---${NC}"

# N. Logout
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/logout" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Normal Logout" "$HTTP_CODE" "200" "$BODY"

# O. Access token invalidated
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Access Invalidated Route After Logout" "$HTTP_CODE" "401" "$BODY"


echo -e "\n========================================================"
echo -e "${CYAN}Integrasi Test Lengkap Selesai!${NC}"
