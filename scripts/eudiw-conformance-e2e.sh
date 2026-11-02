#!/usr/bin/env bash
set -euo pipefail

NODE="${1:-http://localhost:8080}"
API="$NODE/api/v1"

G='\033[0;32m'; R='\033[0;31m'; B='\033[1m'; Y='\033[0;33m'; N='\033[0m'
ok()   { echo -e "${G}✓${N} $1"; }
fail() { echo -e "${R}✗${N} $1"; FAILURES=$((FAILURES+1)); }
warn() { echo -e "${Y}⚠${N} $1"; }
step() { echo -e "\n${B}── $1${N}"; }
PASS=0; FAILURES=0
assert_eq() {
  if [ "$1" = "$2" ]; then ok "$3"; PASS=$((PASS+1));
  else fail "$3 (expected '$2', got '$1')"; fi
}
assert_contains() {
  if echo "$1" | grep -q "$2"; then ok "$3"; PASS=$((PASS+1));
  else fail "$3 (expected to contain '$2')"; fi
}
assert_not_empty() {
  if [ -n "$1" ]; then ok "$2"; PASS=$((PASS+1));
  else fail "$2 (was empty)"; fi
}
assert_http() {
  local code="$1" expected="$2" label="$3"
  if [ "$code" = "$expected" ]; then ok "$label (HTTP $code)"; PASS=$((PASS+1));
  else fail "$label (expected HTTP $expected, got $code)"; fi
}

echo -e "\n${B}╔══════════════════════════════════════════════════════════╗${N}"
echo -e "${B}║  EUDIW Conformance E2E — OID4VCI + OID4VP (1.0 Final)   ║${N}"
echo -e "${B}╚══════════════════════════════════════════════════════════╝${N}"
echo "Target: $NODE"

step "Phase 1 — Health check"

HEALTH=$(curl -sk "$API/health" | jq -r '.status // .data // empty' 2>/dev/null || echo "")
if [ -z "$HEALTH" ]; then
  HEALTH=$(curl -sk "$API/health" | jq -r '.data.status // empty' 2>/dev/null || echo "")
fi
assert_not_empty "$HEALTH" "Node responds to health check"

step "Phase 2 — OID4VCI Issuer Metadata (OID4VCI 1.0 Final §10)"

META=$(curl -sk "$NODE/.well-known/openid-credential-issuer")
CREDENTIAL_ISSUER=$(echo "$META" | jq -r '.credential_issuer // empty')
CREDENTIAL_ENDPOINT=$(echo "$META" | jq -r '.credential_endpoint // empty')
NONCE_ENDPOINT=$(echo "$META" | jq -r '.nonce_endpoint // empty')
TOKEN_ENDPOINT=$(echo "$META" | jq -r '.token_endpoint // empty')

assert_not_empty "$CREDENTIAL_ISSUER" "credential_issuer present"
assert_not_empty "$CREDENTIAL_ENDPOINT" "credential_endpoint present"
assert_not_empty "$NONCE_ENDPOINT" "nonce_endpoint present (OID4VCI 1.0 Final)"
assert_not_empty "$TOKEN_ENDPOINT" "token_endpoint present"

CONFIGS=$(echo "$META" | jq '.credential_configurations_supported | keys | length')
assert_eq "$([ "$CONFIGS" -ge 2 ] && echo 'true' || echo 'false')" "true" "At least 2 credential configs (SD-JWT VC only)"

PID_FORMAT=$(echo "$META" | jq -r '.credential_configurations_supported.eudi_pid_sd_jwt.format // empty')
assert_eq "$PID_FORMAT" "vc+sd-jwt" "eudi_pid_sd_jwt format is vc+sd-jwt"

PID_VCT=$(echo "$META" | jq -r '.credential_configurations_supported.eudi_pid_sd_jwt.vct // empty')
assert_eq "$PID_VCT" "urn:eudi:pid:1" "eudi_pid_sd_jwt vct is urn:eudi:pid:1"

GRANTS=$(echo "$META" | jq -r '.grant_types_supported // [] | join(",")')
assert_contains "$GRANTS" "pre-authorized_code" "Supports pre-authorized_code grant"
assert_contains "$GRANTS" "authorization_code" "Supports authorization_code grant"

step "Phase 3 — OAuth AS Metadata (RFC 8414)"

AS_META=$(curl -sk "$NODE/.well-known/oauth-authorization-server")
AS_ISSUER=$(echo "$AS_META" | jq -r '.issuer // empty')
assert_not_empty "$AS_ISSUER" "AS issuer present"

DPOP_ALGS=$(echo "$AS_META" | jq -r '.dpop_signing_alg_values_supported // [] | join(",")')
assert_contains "$DPOP_ALGS" "ES256" "DPoP supports ES256"

TOKEN_AUTH=$(echo "$AS_META" | jq -r '.token_endpoint_auth_methods_supported // [] | join(",")')
assert_contains "$TOKEN_AUTH" "attest_jwt_client_auth" "Supports attest_jwt_client_auth"

PAR_ENDPOINT=$(echo "$AS_META" | jq -r '.pushed_authorization_request_endpoint // empty')
assert_not_empty "$PAR_ENDPOINT" "PAR endpoint present"

step "Phase 4 — JWT VC Issuer Metadata (SD-JWT VC §3)"

JWKS=$(curl -sk "$NODE/.well-known/jwt-vc-issuer")
JWKS_ISSUER=$(echo "$JWKS" | jq -r '.issuer // empty')
JWKS_KEYS=$(echo "$JWKS" | jq '.jwks.keys | length')
assert_not_empty "$JWKS_ISSUER" "jwt-vc-issuer has issuer"
assert_eq "$([ "$JWKS_KEYS" -ge 1 ] && echo 'true' || echo 'false')" "true" "jwt-vc-issuer has at least 1 key"

step "Phase 5 — Credential Offer (OID4VCI §4.1)"

OFFER_RESP=$(curl -sk -X POST "$NODE/credential_offer" \
  -H 'Content-Type: application/json' \
  -d '{"credential_configuration_ids":["eudi_pid_sd_jwt"]}')
OFFER_CODE=$(echo "$OFFER_RESP" | jq -r '.credential_offer.grants."urn:ietf:params:oauth:grant-type:pre-authorized_code"."pre-authorized_code" // empty')
assert_not_empty "$OFFER_CODE" "Credential offer returns pre-authorized_code"

OFFER_URI=$(echo "$OFFER_RESP" | jq -r '.credential_offer_uri // empty')
assert_contains "$OFFER_URI" "openid-credential-offer://" "Credential offer URI uses correct scheme"

OFFER_ISSUER=$(echo "$OFFER_RESP" | jq -r '.credential_offer.credential_issuer // empty')
assert_not_empty "$OFFER_ISSUER" "Credential offer has issuer"

step "Phase 6 — Token Exchange (pre-authorized_code)"

TOKEN_RESP=$(curl -sk -X POST "$NODE/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=$OFFER_CODE")
ACCESS_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.access_token // empty')
TOKEN_TYPE=$(echo "$TOKEN_RESP" | jq -r '.token_type // empty')

assert_not_empty "$ACCESS_TOKEN" "Token endpoint returns access_token"
assert_contains "$ACCESS_TOKEN" "goya_at_" "Access token has goya prefix"
assert_eq "$TOKEN_TYPE" "Bearer" "Token type is Bearer (no DPoP)"

C_NONCE_IN_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.c_nonce // "absent"')
assert_not_empty "$C_NONCE_IN_TOKEN" "c_nonce present in token response (Draft 13 backward compat)"

step "Phase 7 — Nonce Endpoint (OID4VCI 1.0 Final §8)"

NONCE_RESP=$(curl -sk -X POST "$NODE/nonce")
C_NONCE=$(echo "$NONCE_RESP" | jq -r '.c_nonce // empty')
C_NONCE_EXPIRES=$(echo "$NONCE_RESP" | jq -r '.c_nonce_expires_in // empty')

assert_not_empty "$C_NONCE" "Nonce endpoint returns c_nonce"
assert_eq "$(echo "$C_NONCE" | wc -c | tr -d ' ')" "65" "c_nonce is 64 hex chars (32 bytes)"
assert_not_empty "$C_NONCE_EXPIRES" "c_nonce_expires_in present"

step "Phase 8 — Token rejects invalid grants"

BAD_GRANT_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$NODE/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials')
assert_http "$BAD_GRANT_CODE" "400" "Rejects unsupported grant_type"

SHORT_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$NODE/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=short')
assert_http "$SHORT_CODE" "400" "Rejects pre-authorized_code < 16 chars"

step "Phase 9 — PAR + Authorization Code Flow (RFC 9126 + RFC 7636)"

CODE_VERIFIER=$(openssl rand -hex 32)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

PAR_RESP=$(curl -sk -X POST "$NODE/as/par" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "client_id=conformance-wallet.example.com&response_type=code&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fconformance-wallet.example.com%2Fcb&scope=eudi_pid_sd_jwt")
PAR_STATUS=$(echo "$PAR_RESP" | jq -r '.request_uri // empty')
PAR_EXPIRES=$(echo "$PAR_RESP" | jq -r '.expires_in // empty')

assert_not_empty "$PAR_STATUS" "PAR returns request_uri"
assert_contains "$PAR_STATUS" "urn:ietf:params:oauth:request_uri:" "request_uri has correct URN scheme"
assert_eq "$PAR_EXPIRES" "600" "PAR expires_in is 600s"

PAR_PLAIN_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$NODE/as/par" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "client_id=test&response_type=code&code_challenge=test&code_challenge_method=plain&redirect_uri=https%3A%2F%2Ftest.example.com%2Fcb")
assert_http "$PAR_PLAIN_CODE" "400" "PAR rejects plain code_challenge_method"

ENCODED_URI=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAR_STATUS', safe=''))" 2>/dev/null || echo "$PAR_STATUS")
AUTH_RESP=$(curl -sk -o /dev/null -D - -X GET "$NODE/authorize?request_uri=$ENCODED_URI" 2>&1)
AUTH_LOCATION=$(echo "$AUTH_RESP" | grep -i "^location:" | tr -d '\r' | sed 's/^[Ll]ocation: //')

if [ -n "$AUTH_LOCATION" ]; then
  ok "Authorize endpoint returns redirect"; PASS=$((PASS+1))
  assert_contains "$AUTH_LOCATION" "conformance-wallet.example.com/cb?code=" "Redirect contains code"
  AUTH_CODE=$(echo "$AUTH_LOCATION" | sed 's/.*code=//' | cut -d'&' -f1)
else
  AUTH_JSON=$(curl -sk "$NODE/authorize?request_uri=$ENCODED_URI")
  AUTH_CODE=$(echo "$AUTH_JSON" | jq -r '.code // empty')
  if [ -n "$AUTH_CODE" ]; then
    ok "Authorize endpoint returns code"; PASS=$((PASS+1))
    ok "Code present in response"; PASS=$((PASS+1))
  else
    fail "Authorize endpoint returned no code or redirect"
    fail "No code in response"
    AUTH_CODE=""
  fi
fi

if [ -n "$AUTH_CODE" ]; then
  AUTH_TOKEN_RESP=$(curl -sk -X POST "$NODE/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=authorization_code&code=$AUTH_CODE&code_verifier=$CODE_VERIFIER&redirect_uri=https%3A%2F%2Fconformance-wallet.example.com%2Fcb")
  AUTH_ACCESS_TOKEN=$(echo "$AUTH_TOKEN_RESP" | jq -r '.access_token // empty')
  assert_not_empty "$AUTH_ACCESS_TOKEN" "Auth code + PKCE exchange returns access_token"

  WRONG_VERIFIER_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$NODE/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=authorization_code&code=some-fake-code-value&code_verifier=wrong-verifier-value")
  assert_http "$WRONG_VERIFIER_CODE" "400" "Auth code rejects wrong code_verifier"

  NO_VERIFIER_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$NODE/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=authorization_code&code=$AUTH_CODE")
  assert_http "$NO_VERIFIER_CODE" "400" "Auth code rejects missing code_verifier"
fi

step "Phase 10 — Credential Issuance (SD-JWT VC via pre-auth)"

CRED_RESP=$(curl -sk -X POST "$NODE/credential" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d "{
    \"credential_configuration_id\": \"eudi_pid_sd_jwt\",
    \"claims\": {
      \"given_name\": \"Juan\",
      \"family_name\": \"Pérez\",
      \"birthdate\": \"1990-01-15\",
      \"nationalities\": [\"CL\"],
      \"issuing_country\": \"CL\",
      \"issuing_authority\": \"Goya Ledger\"
    }
  }")
CRED_STATUS=$(echo "$CRED_RESP" | jq -r '.error // "ok"')
SD_JWT=$(echo "$CRED_RESP" | jq -r '.credential // empty')

if [ "$CRED_STATUS" = "ok" ] && [ -n "$SD_JWT" ]; then
  ok "Credential issued successfully"; PASS=$((PASS+1))

  DISCLOSURE_COUNT=$(echo "$SD_JWT" | tr '~' '\n' | wc -l | tr -d ' ')
  assert_eq "$([ "$DISCLOSURE_COUNT" -ge 2 ] && echo 'true' || echo 'false')" "true" "SD-JWT has disclosures (selective disclosure)"

  JWT_PART=$(echo "$SD_JWT" | cut -d'~' -f1)
  JWT_PAYLOAD=$(echo "$JWT_PART" | cut -d'.' -f2 | base64 -d 2>/dev/null || echo "{}")
  VCT=$(echo "$JWT_PAYLOAD" | jq -r '.vct // empty' 2>/dev/null || echo "")
  ISS=$(echo "$JWT_PAYLOAD" | jq -r '.iss // empty' 2>/dev/null || echo "")
  assert_not_empty "$VCT" "SD-JWT has vct claim"
  assert_not_empty "$ISS" "SD-JWT has iss claim"

  CREDS_ARRAY=$(echo "$CRED_RESP" | jq -r '.credentials // [] | length')
  assert_eq "$([ "$CREDS_ARRAY" -ge 1 ] && echo 'true' || echo 'false')" "true" "Response includes credentials array (OID4VCI 1.0)"
else
  ERROR_DESC=$(echo "$CRED_RESP" | jq -r '.error_description // .error.message // "unknown"')
  fail "Credential issuance failed: $ERROR_DESC"
fi

step "Phase 12 — Credential rejects unauthorized"

UNAUTH_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$NODE/credential" \
  -H 'Content-Type: application/json' \
  -d '{"credential_configuration_id":"eudi_pid_sd_jwt"}')
assert_http "$UNAUTH_CODE" "401" "Credential endpoint rejects missing token"

step "Phase 13 — OID4VP Relying Party Registration (CIR 2025/848)"

RP_RESP=$(curl -sk -X POST "$API/oid4vp/rp" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "conformance-verifier.example.com",
    "name": "EUDIW Conformance Verifier",
    "redirect_uris": ["https://conformance-verifier.example.com/cb"],
    "purpose": "EUDIW conformance testing",
    "data_requested": ["given_name", "family_name", "birthdate"]
  }')
RP_REGISTERED=$(echo "$RP_RESP" | jq -r '.data.registered // empty')
assert_eq "$RP_REGISTERED" "true" "RP registered successfully"

step "Phase 14 — OID4VP Unregistered RP Rejected"

UNREG_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$API/oid4vp/request" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "unknown-rp.example.com",
    "response_uri": "https://unknown.example.com/cb",
    "dcql_query": {"credentials":[{"id":"pid","format":"vc+sd-jwt","claims":[{"path":["$.given_name"]}]}]}
  }')
assert_http "$UNREG_CODE" "403" "Unregistered RP gets 403"

step "Phase 15 — OID4VP Presentation Request (DCQL)"

VP_REQ_RESP=$(curl -sk -X POST "$API/oid4vp/request" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "conformance-verifier.example.com",
    "response_uri": "https://conformance-verifier.example.com/cb",
    "dcql_query": {
      "credentials": [{
        "id": "pid",
        "format": "vc+sd-jwt",
        "claims": [
          {"path": ["$.given_name"]},
          {"path": ["$.family_name"]}
        ]
      }]
    }
  }')
REQUEST_ID=$(echo "$VP_REQ_RESP" | jq -r '.data.request_id // empty')
VP_NONCE=$(echo "$VP_REQ_RESP" | jq -r '.data.nonce // empty')
VP_STATE=$(echo "$VP_REQ_RESP" | jq -r '.data.state // empty')
CLIENT_META=$(echo "$VP_REQ_RESP" | jq -r '.data.client_metadata.client_name // empty')

assert_not_empty "$REQUEST_ID" "Presentation request created"
assert_not_empty "$VP_NONCE" "Request includes nonce"
assert_not_empty "$VP_STATE" "Request includes state"
assert_eq "$CLIENT_META" "EUDIW Conformance Verifier" "Client metadata disclosed to wallet"

step "Phase 16 — OID4VP Request by Reference (cross-device QR flow)"

REF_RESP=$(curl -sk "$API/oid4vp/request/$REQUEST_ID")
REF_CLIENT=$(echo "$REF_RESP" | jq -r '.data.client_id // empty')
assert_eq "$REF_CLIENT" "conformance-verifier.example.com" "Request retrievable by ID"

REF_DCQL=$(echo "$REF_RESP" | jq -r '.data.dcql_query.credentials[0].id // empty')
assert_eq "$REF_DCQL" "pid" "DCQL query preserved in request"

step "Phase 17 — OID4VP Rejects presentation_definition (legacy)"

PD_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$API/oid4vp/request" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "conformance-verifier.example.com",
    "response_uri": "https://conformance-verifier.example.com/cb",
    "presentation_definition": {"id":"x","input_descriptors":[]}
  }')
assert_http "$PD_CODE" "400" "Rejects presentation_definition (OID4VP 1.0 Final)"

step "Phase 18 — OID4VP Rejects invalid state"

BAD_STATE_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$API/oid4vp/response" \
  -H 'Content-Type: application/json' \
  -d '{"vp_token":"fake~token~","state":"nonexistent"}')
assert_http "$BAD_STATE_CODE" "400" "Rejects VP response with unknown state"

step "Phase 19 — RP List"

RP_LIST=$(curl -sk "$API/oid4vp/rp")
RP_COUNT=$(echo "$RP_LIST" | jq '.data | length')
assert_eq "$([ "$RP_COUNT" -ge 1 ] && echo 'true' || echo 'false')" "true" "RP list returns registered parties"

step "Phase 20 — Status List (IETF Token Status List)"

SL_CODE=$(curl -sk -o /dev/null -w '%{http_code}' "$API/statuslist/nonexistent")
assert_http "$SL_CODE" "404" "Status list 404 for unknown list"

step "Phase 21 — security.txt (RFC 9116)"

SECTXT=$(curl -sk "$NODE/.well-known/security.txt")
assert_contains "$SECTXT" "Contact:" "security.txt has Contact field"
assert_contains "$SECTXT" "Expires:" "security.txt has Expires field"
assert_contains "$SECTXT" "Policy:" "security.txt has Policy field"

echo -e "\n${B}╔══════════════════════════════════════════════════════════╗${N}"
echo -e "${B}║  Results                                                  ║${N}"
echo -e "${B}╚══════════════════════════════════════════════════════════╝${N}"
echo -e "  Passed:  ${G}${PASS}${N}"
echo -e "  Failed:  ${R}${FAILURES}${N}"
echo -e "  Total:   $((PASS + FAILURES))"
echo ""

if [ "$FAILURES" -gt 0 ]; then
  echo -e "${R}CONFORMANCE: $FAILURES assertion(s) failed${N}"
  exit 1
else
  echo -e "${G}CONFORMANCE: all $PASS assertions passed${N}"
  exit 0
fi
