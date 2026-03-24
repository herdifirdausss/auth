#!/bin/bash

# Configuration
BASE_URL=${1:-"http://localhost:8080"}
LOG_FILE="server.log"

# Generate random user data
TIMESTAMP=$(date +%s)
EMAIL="test_${TIMESTAMP}@example.com"
USERNAME="testuser_${TIMESTAMP}"
PASSWORD="Password123!"
NEW_PASSWORD="NewPassword123!"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

echo -e "${CYAN}=== Blueprint Integration Test (World-Class Auth) ===${NC}"
echo -e "Target URL: $BASE_URL"
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
        exit 1
    fi
}

extract_token_from_log() {
    local pattern=$1
    if [[ ! -f "$LOG_FILE" ]]; then
        echo -e "${RED}[ERROR]${NC} Log file $LOG_FILE not found." >&2
        echo -e "${YELLOW}[TIP]${NC} Run your server like this: 'go run . > $LOG_FILE 2>&1 &'" >&2
        return 1
    fi
    
    sleep 2 # Wait for log to write
    local token=$(grep "$pattern" "$LOG_FILE" | tail -n1 | grep -o "token=[^ ]*" | cut -d'=' -f2)
    
    if [[ -z "$token" ]]; then
        echo -e "${RED}[ERROR]${NC} Could not extract token from $LOG_FILE using pattern '$pattern'" >&2
        return 1
    fi
    echo "$token"
}

# 0. Prerequisites Check
echo -e "${MAGENTA}--- Phase 0: Prerequisites Check ---${NC}"
if ! curl -s "$BASE_URL/health" > /dev/null; then
    # Some older versions might not have /health, try /auth/login with empty body
    if ! curl -s -X POST "$BASE_URL/auth/login" > /dev/null; then
        echo -e "${RED}[ERROR]${NC} Server not reachable at $BASE_URL"
        echo -e "${YELLOW}[TIP]${NC} Start the server with: 'go run . > $LOG_FILE 2>&1 &'"
        exit 1
    fi
fi
echo -e "${GREEN}[PASS]${NC} Server is reachable"

# 1. Register
echo -e "${MAGENTA}--- Phase 1: Registration ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"username\": \"$USERNAME\",
        \"email\": \"$EMAIL\",
        \"password\": \"$PASSWORD\",
        \"tenant_slug\": \"test-tenant\"
    }")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "User Registration" "$HTTP_CODE" "201" "$BODY"

VERIFY_TOKEN=$(extract_token_from_log "email verification token generated.*email=$EMAIL")
echo -e "Verification Token: $VERIFY_TOKEN"

# 2. Login BEFORE verification (Should FAIL)
echo -e "\n${MAGENTA}--- Phase 2: Verification Enforcement ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Login Before Verification (Should fail)" "$HTTP_CODE" "400|401" "$BODY"

# 3. Verify Email
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/verify-email?token=$VERIFY_TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Email Verification" "$HTTP_CODE" "200" "$BODY"

# 4. Login AFTER verification (Should PASS)
echo -e "\n${MAGENTA}--- Phase 3: Login & MFA Setup ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Login After Verification" "$HTTP_CODE" "200" "$BODY"

ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# 5. MFA Setup
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/mfa/setup" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "MFA Setup Initialized" "$HTTP_CODE" "200" "$BODY"

# 6. MFA Verify Setup (Using TEST_MODE "000000")
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/verify-setup" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"otp_code": "000000"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "MFA Setup Verified" "$HTTP_CODE" "200" "$BODY"

# 7. Login with MFA Challenge
echo -e "\n${MAGENTA}--- Phase 4: MFA Challenge & Replay Protection ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Login (MFA Required)" "$HTTP_CODE" "200" "$BODY"

MFA_TOKEN=$(echo "$BODY" | grep -o '"mfa_token":"[^"]*' | cut -d'"' -f4)

# 8. Complete MFA Challenge
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/challenge" \
    -H "Content-Type: application/json" \
    -d "{\"mfa_token\": \"$MFA_TOKEN\", \"otp_code\": \"000000\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "MFA Challenge Completed (000000)" "$HTTP_CODE" "200" "$BODY"

ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# 9. MFA Replay Protection (Try same MFA_TOKEN again)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/challenge" \
    -H "Content-Type: application/json" \
    -d "{\"mfa_token\": \"$MFA_TOKEN\", \"otp_code\": \"000000\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "MFA Replay Protection (Should fail)" "$HTTP_CODE" "401" "$BODY"

# 10. Logout & Session Invalidation
echo -e "\n${MAGENTA}--- Phase 5: Logout & All-Session Revocation ---${NC}"
# Login once more to get second session
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
MFA_TOKEN=$(echo "$BODY" | grep -o '"mfa_token":"[^"]*' | cut -d'"' -f4)

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/challenge" \
    -H "Content-Type: application/json" \
    -d "{\"mfa_token\": \"$MFA_TOKEN\", \"otp_code\": \"000000\"}")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
SESS2_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Call LogoutAll with Sess2
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/logout-all" \
    -H "Authorization: Bearer $SESS2_TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Logout All Sessions" "$HTTP_CODE" "200" "$BODY"

# Verify Sess1 is invalid
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Session 1 Invalidated after LogoutAll" "$HTTP_CODE" "401" "$BODY"

# 11. Password History Violation
echo -e "\n${MAGENTA}--- Phase 6: Password Policies & History ---${NC}"
# Need reset token
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/forgot-password" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\"}")
RESET_TOKEN=$(extract_token_from_log "password reset token generated.*email=$EMAIL")

# Reset to NEW password
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/reset-password" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$RESET_TOKEN\", \"new_password\": \"$NEW_PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Reset to New Password" "$HTTP_CODE" "200" "$BODY"

# Try to reset BACK to old password (History violation)
# Need another token
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/forgot-password" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\"}")
RESET_TOKEN2=$(extract_token_from_log "password reset token generated.*email=$EMAIL")

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/reset-password" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$RESET_TOKEN2\", \"new_password\": \"$PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Reset to OLD Password (Should fail)" "$HTTP_CODE" "400" "$BODY"

# 12. Login with New Password
echo -e "\n${MAGENTA}--- Phase 7: Validating New Password Login ---${NC}"
# Clear redis rate limits for integration testing (IP based block)
redis-cli flushdb || true

# Login with old password (Should fail)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Login with Old Password (Should fail)" "$HTTP_CODE" "401" "$BODY"

# Login with new password
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$NEW_PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Login with New Password" "$HTTP_CODE" "200" "$BODY"

# Complete MFA Challenge to get tokens
MFA_TOKEN=$(echo "$BODY" | grep -o '"mfa_token":"[^"]*' | cut -d'"' -f4)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/challenge" \
    -c cookies.txt \
    -H "Content-Type: application/json" \
    -d "{\"mfa_token\": \"$MFA_TOKEN\", \"otp_code\": \"000000\"}")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
NEW_ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# 13. Token Refresh
echo -e "\n${MAGENTA}--- Phase 8: Token Refresh ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/token/refresh" \
    -b cookies.txt)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Token Refresh" "$HTTP_CODE" "200" "$BODY"
REFRESHED_ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# 14. Normal Logout
echo -e "\n${MAGENTA}--- Phase 9: Single Session Logout ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/logout" \
    -H "Authorization: Bearer $REFRESHED_ACCESS_TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Single Logout" "$HTTP_CODE" "200" "$BODY"

# Verify token is invalidated
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer $REFRESHED_ACCESS_TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Token Invalidated After Logout" "$HTTP_CODE" "401" "$BODY"

echo -e "\n========================================================"
echo -e "${GREEN}ALL BLUEPRINT TESTS PASSED!${NC}"
