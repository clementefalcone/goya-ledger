#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Goya LexChain FES end-to-end demo
#
# Deploys an NDA contract, creates two DIDs, signs as both
# parties with FES (Ed25519), and retrieves the fully signed
# contract — all against a running Goya node.
#
# Usage:
#   ./scripts/try-fes.sh                    # default: localhost:8080
#   ./scripts/try-fes.sh http://127.0.0.1:8080     # explicit node
# ─────────────────────────────────────────────────────────────
set -euo pipefail

NODE="${1:-http://localhost:8080}"
API="$NODE/api/v1"
SIGN_BIN="${SIGN_BIN:-./target/debug/goya-sign}"

command -v curl >/dev/null || { echo "curl required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
[ -x "$SIGN_BIN" ] || { echo "goya-sign not found. Run: cargo build --bin goya-sign"; exit 1; }

G='\033[0;32m'; R='\033[0;31m'; B='\033[1m'; N='\033[0m'

ok()   { echo -e "${G}✓${N} $1"; }
fail() { echo -e "${R}✗${N} $1"; exit 1; }
step() { echo -e "\n${B}── $1${N}"; }
field() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }

register() {
  local did="$1" pk="$2" sk="$3" now sig
  now=$(date +%s)
  sig=$($SIGN_BIN sign ed25519 "$sk" "identity:register:$did" | field "['signature']")
  curl -sf -X POST "$API/store/identities" \
    -H "Content-Type: application/json" \
    -d "{\"did\":\"$did\",\"public_key\":\"$pk\",\"created_at\":$now,\"updated_at\":$now,\"status\":\"active\",\"signature\":\"$sig\"}" >/dev/null
}

sign_body() {
  local did="$1" pk="$2" sk="$3" payload="$4" sig
  sig=$($SIGN_BIN sign ed25519 "$sk" "$payload" | field "['signature']")
  printf '{"did":"%s","signature":"%s","public_key":"%s"}' "$did" "$sig" "$pk"
}

# ── 1. Health check ──────────────────────────────────────────
step "Health check"
curl -sf "$API/health" >/dev/null 2>&1 || fail "Node unreachable at $NODE"
ok "Node alive at $NODE"

# ── 2. Create two DIDs ───────────────────────────────────────
step "Creating identities (DID = SHA3-512 of the public key)"

alice_kp=$($SIGN_BIN keygen ed25519)
alice_did=$(echo "$alice_kp" | field "['did']")
alice_pk=$(echo "$alice_kp" | field "['public_key']")
alice_sk=$(echo "$alice_kp" | field "['private_key']")

bob_kp=$($SIGN_BIN keygen ed25519)
bob_did=$(echo "$bob_kp" | field "['did']")
bob_pk=$(echo "$bob_kp" | field "['public_key']")
bob_sk=$(echo "$bob_kp" | field "['private_key']")

register "$alice_did" "$alice_pk" "$alice_sk" || fail "Failed to register Alice"
ok "Alice: ${alice_did:0:30}..."
register "$bob_did" "$bob_pk" "$bob_sk" || fail "Failed to register Bob"
ok "Bob:   ${bob_did:0:30}..."

# ── 3. Deploy NDA contract ──────────────────────────────────
step "Deploying NDA contract"

deploy_body=$(python3 -c "
import json
print(json.dumps({
    'type': 'non_disclosure_agreement',
    'parties': [
        {'role': 'discloser', 'did': '$alice_did', 'signature_level': 'simple'},
        {'role': 'recipient', 'did': '$bob_did', 'signature_level': 'simple'}
    ],
    'payload': {'scope': 'Project X confidential materials', 'effective_date': '2026-08-18'},
    'require_notarization': True,
    'deadline_secs': 86400
}))
")

deploy_resp=$(curl -sf -X POST "$API/lexchain/deploy" \
  -H "Content-Type: application/json" \
  -d "$deploy_body") || fail "Deploy failed"

contract_id=$(echo "$deploy_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['id'])")
content_hash=$(echo "$deploy_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['content_hash'])")
state=$(echo "$deploy_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['state'])")

ok "Contract: $contract_id"
ok "Hash:     $content_hash"
ok "State:    $state"

[ "$state" = "pending_signatures" ] || fail "Expected pending_signatures, got $state"

# ── 4. Impersonation attempt ────────────────────────────────
step "Bob tries to sign as Alice with his own key (must be rejected)"

forged=$(sign_body "$alice_did" "$bob_pk" "$bob_sk" "fes:${alice_did}:${content_hash}")
forged_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/lexchain/$contract_id/sign" \
  -H "Content-Type: application/json" -d "$forged")
[ "$forged_code" = "400" ] || fail "Impersonation not rejected (HTTP $forged_code)"
ok "Rejected with HTTP $forged_code"

# ── 5. Alice signs (FES) ────────────────────────────────────
step "Alice signs (FES / Ed25519)"

sign_alice_resp=$(curl -sf -X POST "$API/lexchain/$contract_id/sign" \
  -H "Content-Type: application/json" \
  -d "$(sign_body "$alice_did" "$alice_pk" "$alice_sk" "fes:${alice_did}:${content_hash}")") \
  || fail "Alice sign failed"
state_after_alice=$(echo "$sign_alice_resp" | field "['data']['state']")
ok "Alice signed → state: $state_after_alice"
[ "$state_after_alice" = "pending_signatures" ] || fail "Expected pending_signatures after first sign"

# ── 6. Bob signs (FES) ──────────────────────────────────────
step "Bob signs (FES / Ed25519)"

sign_bob_resp=$(curl -sf -X POST "$API/lexchain/$contract_id/sign" \
  -H "Content-Type: application/json" \
  -d "$(sign_body "$bob_did" "$bob_pk" "$bob_sk" "fes:${bob_did}:${content_hash}")") \
  || fail "Bob sign failed"
final_state=$(echo "$sign_bob_resp" | field "['data']['state']")
ok "Bob signed → state: $final_state"

case "$final_state" in
  notarized)   ok "Contract notarized with TSA timestamp" ;;
  fully_signed) ok "Contract fully signed (TSA not configured on node)" ;;
  *) fail "Unexpected final state: $final_state" ;;
esac

# ── 7. Retrieve final contract ──────────────────────────────
step "Retrieving signed contract"

get_resp=$(curl -sf "$API/lexchain/$contract_id") || fail "GET contract failed"

echo "$get_resp" | python3 -c "
import sys, json
c = json.load(sys.stdin)['data']
print(f'  Contract:  {c[\"id\"]}')
print(f'  Type:      {c[\"definition\"].get(\"type\", c[\"definition\"].get(\"contract_type\",\"?\"))}')
print(f'  State:     {c[\"state\"]}')
print(f'  Parties:   {len(c[\"parties\"])}')
for p in c['parties']:
    sig_algo = p.get('envelope',{}).get('signature_algorithm','—') if p.get('envelope') else '—'
    print(f'    {p[\"role\"]:12} {p[\"did\"][:30]}... signed={p[\"signed\"]}  algo={sig_algo}')
if c.get('tsa_token'):
    print(f'  TSA:       serial={c[\"tsa_token\"][\"tst_info\"][\"serial_number\"]}')
print(f'  Hash:      {c[\"content_hash\"][:16]}...')
"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${G}${B}FES end-to-end complete.${N}"
echo -e "Contract $contract_id signed by both parties with Ed25519."
echo -e "15 lines of JSON → legally valid NDA with cryptographic proof."
