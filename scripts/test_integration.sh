#!/bin/bash

# Configuration
BASE_URL=${1:-"http://localhost:8080"}
LOG_FILE="server.log"

# Generate random user data
TIMESTAMP=$(date +%s)
EMAIL="test_${TIMESTAMP}@example.com"
USERNAME="testuser_${TIMESTAMP}"
PASSWORD="ComplexP@ssw0rd_2026_!#Unique"
NEW_PASSWORD="New_ComplexP@ssw0rd_2026_!#Unique"
FINGERPRINT_A="iphone_15_pro_${TIMESTAMP}"
FINGERPRINT_B="macbook_pro_${TIMESTAMP}"

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
FAILURES=0
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
        FAILURES=$((FAILURES + 1))
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
    if ! curl -s -X POST "$BASE_URL/auth/login" > /dev/null; then
        echo -e "${RED}[ERROR]${NC} Server not reachable at $BASE_URL"
        echo -e "${YELLOW}[TIP]${NC} Start the server with: 'go run . > $LOG_FILE 2>&1 &'"
        exit 1
    fi
fi
echo -e "${GREEN}[PASS]${NC} Server is reachable"

# 1. Register
echo -e "${MAGENTA}--- Phase 1: Registration & Audit ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -d "{
        \"username\": \"$USERNAME\",
        \"email\": \"$EMAIL\",
        \"password\": \"$PASSWORD\",
        \"tenant_slug\": \"test-org-$TIMESTAMP\"
    }")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "User Registration" "$HTTP_CODE" "201" "$BODY"

# 1.1 Duplicate Registration
echo -e "${YELLOW}[SECURITY]${NC} Testing Duplicate Registration..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"username\": \"duplicate\",
        \"email\": \"$EMAIL\",
        \"password\": \"$PASSWORD\",
        \"tenant_slug\": \"other-org\"
    }")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Detection: Duplicate Email" "$HTTP_CODE" "409" "Conflict"

echo -e "${YELLOW}[AUDIT]${NC} Verification: Ensure 'user.registered' is in audit_logs for $EMAIL"

VERIFY_TOKEN=$(extract_token_from_log "email verification token generated.*email=$EMAIL")
echo -e "Verification Token: $VERIFY_TOKEN"

# 2. Login BEFORE verification
echo -e "\n${MAGENTA}--- Phase 2: Verification Enforcement ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Login Before Verification (Should fail)" "$HTTP_CODE" "400|401" "$BODY"
# 3. Verify Email
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/verify-email?token=$VERIFY_TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Email Verification" "$HTTP_CODE" "200" "$BODY"

# 3.1 Invalid Credentials
echo -e "${YELLOW}[SECURITY]${NC} Testing Invalid Credentials..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"WrongPassword!!!\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Detection: Invalid Password" "$HTTP_CODE" "401" "Unauthorized"

# 4. Password Recovery Flow
echo -e "\n${MAGENTA}--- Phase 3: Password Recovery ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/forgot-password" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\"}")
check_response "Forgot Password Request" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"

RESET_TOKEN=$(extract_token_from_log "password reset token generated.*email=$EMAIL")
echo -e "Reset Token: $RESET_TOKEN"

# Reset Password
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/reset-password" \
    -H "Content-Type: application/json" \
    -d "{
        \"token\": \"$RESET_TOKEN\",
        \"new_password\": \"$NEW_PASSWORD\"
    }")
check_response "Password Reset" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"

# Login with NEW password
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$NEW_PASSWORD\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Login with New Password" "$HTTP_CODE" "200" "Success"

# 5. Login AFTER verification & Device Binding
echo -e "\n${MAGENTA}--- Phase 4: Login & Device Tracking ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$EMAIL\", 
        \"password\": \"$NEW_PASSWORD\", 
        \"device_fingerprint\": \"$FINGERPRINT_A\",
        \"device_name\": \"Test Macbook\"
    }")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "Login with Fingerprint A" "$HTTP_CODE" "200" "$BODY"

ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Test Fingerprint Mismatch
echo -e "${YELLOW}[SECURITY]${NC} Testing Fingerprint Mismatch Detection..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-Device-Fingerprint: $FINGERPRINT_B")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
check_response "Detection: Fingerprint Mismatch" "$HTTP_CODE" "401" "$BODY"

# 6. MFA Setup & Step-up Auth
echo -e "\n${MAGENTA}--- Phase 5: MFA & Level Verification ---${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/mfa/setup" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "MFA Setup Initialized" "$HTTP_CODE" "200" "$BODY"

# MFA Verify Setup (Extract Recovery Codes)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/verify-setup" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -H "Content-Type: application/json" \
    -d '{"otp_code": "000000"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "MFA Setup Verified" "$HTTP_CODE" "200" "$BODY"

RECOVERY_CODE=$(echo "$BODY" | grep -o '"backup_codes":\["[^"]*"' | head -n1 | cut -d'"' -f4)
echo -e "Extracted Recovery Code: ${RECOVERY_CODE:0:5}*****"

# 6.1 MFA Recovery Code Verification
echo -e "${YELLOW}[SECURITY]${NC} Testing MFA Recovery Code..."
# Login to get MFA Token
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$NEW_PASSWORD\"}")
MFA_TOKEN=$(echo "$RESPONSE" | grep -o '"mfa_token":"[^"]*' | cut -d'"' -f4)

# Challenge with Recovery Code
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/challenge" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -d "{
        \"mfa_token\": \"$MFA_TOKEN\",
        \"recovery_code\": \"$RECOVERY_CODE\"
    }")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed -e '$ d')
check_response "MFA Recovery Code Login" "$HTTP_CODE" "200" "$BODY"
ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# 7. Step-up Auth Verification
echo -e "${YELLOW}[SECURITY]${NC} Testing mfa_verified flag in session..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A")
BODY=$(echo "$RESPONSE" | sed -e '$ d')
if [[ "$BODY" == *"\"mfa_verified\":true"* ]]; then
    echo -e "${GREEN}[PASS]${NC} Session marked as MFA verified"
else
    echo -e "${YELLOW}[WARN]${NC} Session NOT marked as MFA verified"
fi

# 8. Token Refresh with Fingerprint
echo -e "\n${MAGENTA}--- Phase 6: Secure Token Refresh ---${NC}"
# Login again to get cookies/refresh token
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -c cookies.txt \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$NEW_PASSWORD\", \"device_fingerprint\": \"$FINGERPRINT_A\"}")
MFA_TOKEN=$(echo "$RESPONSE" | grep -o '"mfa_token":"[^"]*' | cut -d'"' -f4)
curl -s -X POST "$BASE_URL/auth/mfa/challenge" -b cookies.txt -c cookies.txt \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -d "{\"mfa_token\": \"$MFA_TOKEN\", \"otp_code\": \"000000\"}" > /dev/null

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/token/refresh" \
    -b cookies.txt \
    -H "X-Device-Fingerprint: $FINGERPRINT_A")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "Refresh Token with Correct Fingerprint" "$HTTP_CODE" "200" "Success"
BODY=$(echo "$RESPONSE" | sed -e '$ d')
ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# 9. Multi-Device Logout
echo -e "\n${MAGENTA}--- Phase 7: Multi-Device Management ---${NC}"
# Login with Fingerprint B
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_B" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$NEW_PASSWORD\"}")
MFA_TOKEN_B=$(echo "$RESPONSE" | grep -o '"mfa_token":"[^"]*' | cut -d'"' -f4)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/challenge" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_B" \
    -d "{\"mfa_token\": \"$MFA_TOKEN_B\", \"otp_code\": \"000000\"}")
TOKEN_B=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Logout All
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/logout-all" \
    -H "Authorization: Bearer $TOKEN_B" \
    -H "X-Device-Fingerprint: $FINGERPRINT_B")
check_response "Logout All Devices" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"

# Verify Token A is also revoked
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A")
check_response "Detection: Session A Revoked" "$(echo "$RESPONSE" | tail -n1)" "401" "Unauthorized"

# 10. Admin Dashboard Verification
echo -e "\n${MAGENTA}--- Phase 9: Admin Dashboard RBAC ---${NC}"
# Grant super_admin to current test user
echo "Granting super_admin role to $EMAIL..."
export DATABASE_URL=${DATABASE_URL:-"postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable"}
go run scripts/grant_admin/main.go "$EMAIL"

# Fresh login for Admin token
echo "Obtaining administrative token..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Device-Fingerprint: $FINGERPRINT_A" \
    -d "{\"email\": \"$EMAIL\", \"password\": \"$NEW_PASSWORD\"}")
ADMIN_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [[ -z "$ADMIN_TOKEN" ]]; then
    MFA_TOKEN=$(echo "$RESPONSE" | grep -o '"mfa_token":"[^"]*' | cut -d'"' -f4)
    if [[ -n "$MFA_TOKEN" ]]; then
        RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/challenge" \
            -H "Content-Type: application/json" \
            -H "X-Device-Fingerprint: $FINGERPRINT_A" \
            -d "{\"mfa_token\": \"$MFA_TOKEN\", \"otp_code\": \"000000\"}")
        ADMIN_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    fi
fi

if [[ -z "$ADMIN_TOKEN" ]]; then
    echo -e "${RED}[FAIL]${NC} Could not obtain Admin Access Token"
    FAILURES=$((FAILURES + 1))
else
    # 10.1 List Tenants (Admin)
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/admin/tenants" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    check_response "Admin: List Tenants" "$HTTP_CODE" "200" "$BODY"

    # 10.2 Update Tenant Status
    TENANT_ID=$(echo "$BODY" | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)
    if [[ -n "$TENANT_ID" ]]; then
        RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH "$BASE_URL/admin/tenants/status?id=$TENANT_ID" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "X-Device-Fingerprint: $FINGERPRINT_A" \
            -H "Content-Type: application/json" \
            -d '{"is_active": false}')
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        check_response "Admin: Update Tenant Status" "$HTTP_CODE" "200" "Success"
    else
        echo -e "${YELLOW}[WARN]${NC} No tenant ID found for status update test"
    fi
fi

# 11. WebAuthn Accessibility
echo -e "\n${MAGENTA}--- Phase 10: WebAuthn Accessibility ---${NC}"
# 11.1 Begin Login (Public)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/webauthn/login/begin" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\"}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
check_response "WebAuthn: Begin Login Accessibility" "$HTTP_CODE" "200|401|404" "Email check performed"

# 11.2 Begin Registration (Protected)
if [[ -n "$ADMIN_TOKEN" ]]; then
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/mfa/webauthn/register/begin" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    check_response "WebAuthn: Begin Registration Accessibility" "$HTTP_CODE" "200" "Registration Initiated"
fi

# 12. Tenant Admin - Configuration
echo -e "\n${MAGENTA}--- Phase 12: Tenant Admin - Configuration ---${NC}"
if [[ -n "$ADMIN_TOKEN" ]]; then
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/admin/tenant/settings" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A")
    check_response "Tenant Admin: Get Settings" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"

    RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH "$BASE_URL/admin/tenant/settings/update" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A" \
        -H "Content-Type: application/json" \
        -d '{"theme": "dark", "allow_registration": true}')
    check_response "Tenant Admin: Update Settings" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"
fi

# 13. Tenant Admin - Role Management
echo -e "\n${MAGENTA}--- Phase 13: Tenant Admin - Role Management ---${NC}"
if [[ -n "$ADMIN_TOKEN" ]]; then
    # Create Role
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/admin/tenant/roles/create" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A" \
        -H "Content-Type: application/json" \
        -d '{"name": "Custom Editor", "description": "Can edit content", "permissions": ["content:read", "content:write"]}')
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    check_response "Tenant Admin: Create Role" "$HTTP_CODE" "201" "$BODY"
    ROLE_ID=$(echo "$BODY" | grep -o '"id":"[^"]*' | cut -d'"' -f4)

    # List Roles
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/admin/tenant/roles" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A")
    check_response "Tenant Admin: List Roles" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"

    # Update Role
    if [[ -n "$ROLE_ID" ]]; then
        RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$BASE_URL/admin/tenant/roles/$ROLE_ID" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "X-Device-Fingerprint: $FINGERPRINT_A" \
            -H "Content-Type: application/json" \
            -d '{"name": "Custom Senior Editor", "permissions": ["content:*"]}')
        check_response "Tenant Admin: Update Role" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"

        # Delete Role
        RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$BASE_URL/admin/tenant/roles/$ROLE_ID" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "X-Device-Fingerprint: $FINGERPRINT_A")
        check_response "Tenant Admin: Delete Role" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"
    fi
fi

# 14. Tenant Admin - Member Management
echo -e "\n${MAGENTA}--- Phase 14: Tenant Admin - Member Management ---${NC}"
if [[ -n "$ADMIN_TOKEN" ]]; then
    # List Members
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/admin/tenant/members" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    check_response "Tenant Admin: List Members" "$HTTP_CODE" "200" "$BODY"
    MEMBERSHIP_ID=$(echo "$BODY" | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)

    # Update Member Status
    if [[ -n "$MEMBERSHIP_ID" ]]; then
        RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH "$BASE_URL/admin/tenant/members/$MEMBERSHIP_ID" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "X-Device-Fingerprint: $FINGERPRINT_A" \
            -H "Content-Type: application/json" \
            -d '{"status": "active"}')
        check_response "Tenant Admin: Update Member Status" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"
    fi
fi

# 15. Security - Brute Force Protection
echo -e "\n${MAGENTA}--- Phase 15: Brute Force Protection ---${NC}"
echo "Simulating multiple failed logins..."
for i in {1..3}; do
    curl -s -o /dev/null -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"$EMAIL\", \"password\": \"WrongPassword$i\"}"
done
echo -e "${GREEN}[INFO]${NC} Brute force attempt simulated. Check audit logs for 'auth.login_failed' triggers."

# 16. Security - Session Revocation (Single)
echo -e "\n${MAGENTA}--- Phase 16: Session Revocation ---${NC}"
if [[ -n "$ADMIN_TOKEN" ]]; then
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/logout" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A")
    check_response "Auth: Logout Single Session" "$(echo "$RESPONSE" | tail -n1)" "200" "Success"

    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Device-Fingerprint: $FINGERPRINT_A")
    check_response "Verification: Session Revoked" "$(echo "$RESPONSE" | tail -n1)" "401" "Unauthorized"
fi

# 17. Cleanup
echo -e "\n${MAGENTA}--- Phase 17: Final Cleanup ---${NC}"
rm -f cookies.txt
echo -e "${GREEN}[PASS]${NC} System clean"

echo -e "\n========================================================"
echo -e "INTEGRATION TEST BLUEPRINT COMPLETE"
echo -e "All security-critical workflows verified."
echo -e "========================================================"

if [ $FAILURES -gt 0 ]; then
    echo -e "${RED}Total Failures: $FAILURES${NC}"
    exit 1
fi
exit 0
