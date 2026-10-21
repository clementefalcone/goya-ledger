#!/usr/bin/env bash
set -euo pipefail

# Smoke test: Optimistic ML Oracle against a live node
# Usage: ./scripts/test-inference.sh [host]
#
# Default: local node (cargo run or docker compose sandbox on :8080)

HOST="${1:-http://127.0.0.1:8080}"
API="$HOST/api/v1"
PASS=0
FAIL=0
TOTAL=0

green() { printf "\033[32m✓ %s\033[0m\n" "$1"; }
red()   { printf "\033[31m✗ %s\033[0m\n" "$1"; }

assert_status() {
    local desc="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" = "$expected" ]; then
        green "$desc (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        red "$desc — expected $expected, got $actual"
        FAIL=$((FAIL + 1))
    fi
}

assert_json() {
    local desc="$1" path="$2" expected="$3" json="$4"
    TOTAL=$((TOTAL + 1))
    local actual
    actual=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin)$path)" 2>/dev/null || echo "PARSE_ERROR")
    if [ "$actual" = "$expected" ]; then
        green "$desc ($path=$actual)"
        PASS=$((PASS + 1))
    else
        red "$desc — $path expected '$expected', got '$actual'"
        FAIL=$((FAIL + 1))
    fi
}

echo "==> Smoke testing Optimistic ML Oracle at $API"
echo ""

# ── Generate Ed25519 keypair + signatures using python ───────────────────────

# We use python3 + hashlib for signing since bash can't do Ed25519
KEYS=$(python3 -c "
from hashlib import sha256
import os, json

# Generate deterministic test keys (not real Ed25519, just for hash proofs)
model_hash = 'a' * 64
input_hash = 'b' * 64
output_hash = 'c' * 64

# SHA256 commitment for proven submit
commitment = sha256((model_hash + input_hash + output_hash).encode()).hexdigest()

print(json.dumps({
    'model_hash': model_hash,
    'input_hash': input_hash,
    'output_hash': output_hash,
    'commitment': commitment,
}))
")

MODEL_HASH=$(echo "$KEYS" | python3 -c "import sys,json; print(json.load(sys.stdin)['model_hash'])")
INPUT_HASH=$(echo "$KEYS" | python3 -c "import sys,json; print(json.load(sys.stdin)['input_hash'])")
OUTPUT_HASH=$(echo "$KEYS" | python3 -c "import sys,json; print(json.load(sys.stdin)['output_hash'])")
COMMITMENT=$(echo "$KEYS" | python3 -c "import sys,json; print(json.load(sys.stdin)['commitment'])")

# ── Phase 1: List claims (empty) ─────────────────────────────────────────────

echo "── Phase 1: Submit + Query ──"

RESP=$(curl -s -w "\n%{http_code}" "$API/inference/claims")
HTTP=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -1)
assert_status "GET /inference/claims (initial)" "200" "$HTTP"

# ── Phase 1: Submit claim (will fail sig check but validates flow) ────────────

RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/inference/submit" \
    -H "Content-Type: application/json" \
    -d "{
        \"oracle_id\": \"oracle-smoke-test\",
        \"model_hash\": \"$MODEL_HASH\",
        \"model_version\": \"v1.0-smoke\",
        \"input_hash\": \"$INPUT_HASH\",
        \"output\": \"{\\\"result\\\": 42}\",
        \"output_hash\": \"$OUTPUT_HASH\",
        \"signature\": \"$(python3 -c "print('dd' * 64)")\",
        \"public_key\": \"$(python3 -c "print('ee' * 32)")\"
    }")
HTTP=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -1)

# Expect 400 (oracle not registered in oracle_registry) or 401 (bad sig)
# The oracle is staked but not registered in the oracle registry
if [ "$HTTP" = "400" ] || [ "$HTTP" = "401" ]; then
    green "POST /inference/submit — correctly rejected unregistered oracle (HTTP $HTTP)"
    PASS=$((PASS + 1))
else
    red "POST /inference/submit — unexpected HTTP $HTTP"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

echo ""

# ── Phase 1: List models ─────────────────────────────────────────────────────

RESP=$(curl -s -w "\n%{http_code}" "$API/inference/models")
HTTP=$(echo "$RESP" | tail -1)
assert_status "GET /inference/models" "200" "$HTTP"

# ── Phase 1: Get nonexistent claim ───────────────────────────────────────────

RESP=$(curl -s -w "\n%{http_code}" "$API/inference/claims/nonexistent-id")
HTTP=$(echo "$RESP" | tail -1)
assert_status "GET /inference/claims/{id} (404)" "404" "$HTTP"

# ── Phase 1: Finalize nonexistent ─────────────────────────────────────────────

RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/inference/finalize/nonexistent-id")
HTTP=$(echo "$RESP" | tail -1)
assert_status "POST /inference/finalize (404)" "404" "$HTTP"

echo ""

# ── Phase 2: Challenge nonexistent claim ──────────────────────────────────────

echo "── Phase 2: Challenge ──"

RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/inference/challenge" \
    -H "Content-Type: application/json" \
    -d "{
        \"claim_id\": \"nonexistent\",
        \"challenger_id\": \"challenger-smoke-test\",
        \"challenger_output\": \"{}\",
        \"challenger_output_hash\": \"$(python3 -c "print('ff' * 32)")\",
        \"signature\": \"$(python3 -c "print('dd' * 64)")\",
        \"public_key\": \"$(python3 -c "print('ee' * 32)")\"
    }")
HTTP=$(echo "$RESP" | tail -1)
assert_status "POST /inference/challenge (nonexistent claim)" "404" "$HTTP"

echo ""

# ── Phase 4: Submit proven with bad proof ─────────────────────────────────────

echo "── Phase 4: zkML Bridge ──"

RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/inference/submit-proven" \
    -H "Content-Type: application/json" \
    -d "{
        \"oracle_id\": \"oracle-smoke-test\",
        \"model_hash\": \"$MODEL_HASH\",
        \"model_version\": \"v1.0-smoke\",
        \"input_hash\": \"$INPUT_HASH\",
        \"output\": \"{\\\"result\\\": 42}\",
        \"output_hash\": \"$OUTPUT_HASH\",
        \"signature\": \"$(python3 -c "print('dd' * 64)")\",
        \"public_key\": \"$(python3 -c "print('ee' * 32)")\",
        \"proof\": {
            \"proof_type\": \"Sha256Commitment\",
            \"proof_data\": \"$(python3 -c "print('ff' * 32)")\"
        }
    }")
HTTP=$(echo "$RESP" | tail -1)
# Expect 400 (oracle not registered or bad proof)
if [ "$HTTP" = "400" ] || [ "$HTTP" = "401" ]; then
    green "POST /inference/submit-proven (bad proof) — correctly rejected (HTTP $HTTP)"
    PASS=$((PASS + 1))
else
    red "POST /inference/submit-proven — unexpected HTTP $HTTP"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

# Submit proven with unsupported proof type
RESP=$(curl -s -w "\n%{http_code}" -X POST "$API/inference/submit-proven" \
    -H "Content-Type: application/json" \
    -d "{
        \"oracle_id\": \"oracle-smoke-test\",
        \"model_hash\": \"$MODEL_HASH\",
        \"model_version\": \"v1.0-smoke\",
        \"input_hash\": \"$INPUT_HASH\",
        \"output\": \"{}\",
        \"output_hash\": \"$OUTPUT_HASH\",
        \"signature\": \"$(python3 -c "print('dd' * 64)")\",
        \"public_key\": \"$(python3 -c "print('ee' * 32)")\",
        \"proof\": {
            \"proof_type\": \"Groth16Bn254\",
            \"proof_data\": \"abcdef\",
            \"verification_key\": \"vk\"
        }
    }")
HTTP=$(echo "$RESP" | tail -1)
if [ "$HTTP" = "400" ]; then
    green "POST /inference/submit-proven (unsupported Groth16) — correctly rejected (HTTP $HTTP)"
    PASS=$((PASS + 1))
else
    red "POST /inference/submit-proven (unsupported type) — unexpected HTTP $HTTP"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

echo ""

# ── Staking endpoints ─────────────────────────────────────────────────────────

echo "── Staking endpoints ──"

RESP=$(curl -s -w "\n%{http_code}" "$API/staking/validators")
HTTP=$(echo "$RESP" | tail -1)
assert_status "GET /staking/validators" "200" "$HTTP"

RESP=$(curl -s -w "\n%{http_code}" "$API/staking/validator/oracle-smoke-test")
HTTP=$(echo "$RESP" | tail -1)
# May be 200 if staked or 404 if staking failed (low balance)
if [ "$HTTP" = "200" ] || [ "$HTTP" = "404" ]; then
    green "GET /staking/validator/{address} (HTTP $HTTP)"
    PASS=$((PASS + 1))
else
    red "GET /staking/validator/{address} — unexpected HTTP $HTTP"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

RESP=$(curl -s -w "\n%{http_code}" "$API/staking/my-stake/oracle-smoke-test")
HTTP=$(echo "$RESP" | tail -1)
if [ "$HTTP" = "200" ] || [ "$HTTP" = "404" ]; then
    green "GET /staking/my-stake/{address} (HTTP $HTTP)"
    PASS=$((PASS + 1))
else
    red "GET /staking/my-stake/{address} — unexpected HTTP $HTTP"
    FAIL=$((FAIL + 1))
fi
TOTAL=$((TOTAL + 1))

echo ""

# ── Summary ───────────────────────────────────────────────────────────────────

echo "════════════════════════════════════════"
echo "  Results: $PASS/$TOTAL passed, $FAIL failed"
echo "════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
