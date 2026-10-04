#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Goya LexChain FEA end-to-end demo
#
# Deploys a Power of Attorney contract requiring Advanced
# Electronic Signatures (FEA): ML-DSA-65 (FIPS 204) post-quantum
# signatures + biometric evidence. Both parties sign with PQC.
#
# Usage:
#   ./scripts/try-fea.sh                    # default: localhost:8080
#   ./scripts/try-fea.sh http://127.0.0.1:8080
#
# Requires: goya-sign binary (cargo build --bin goya-sign)
# ─────────────────────────────────────────────────────────────
set -euo pipefail

NODE="${1:-http://localhost:8080}"
API="$NODE/api/v1"
SIGN_BIN="${SIGN_BIN:-./target/debug/goya-sign}"

command -v curl >/dev/null || { echo "curl required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
[ -x "$SIGN_BIN" ] || { echo "goya-sign not found. Run: cargo build --bin goya-sign"; exit 1; }

G='\033[0;32m'; R='\033[0;31m'; B='\033[1m'; C='\033[0;36m'; N='\033[0m'
ok()   { echo -e "${G}✓${N} $1"; }
fail() { echo -e "${R}✗${N} $1"; exit 1; }
step() { echo -e "\n${B}── $1${N}"; }
info() { echo -e "${C}  $1${N}"; }

jq_() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }

# ── 1. Health ────────────────────────────────────────────────
step "Health check"
curl -sf "$API/health" >/dev/null 2>&1 || fail "Node unreachable at $NODE"
ok "Node alive at $NODE"

# ── 2. Generate ML-DSA-65 keypairs ───────────────────────────
step "Generating ML-DSA-65 keypairs (FIPS 204)"

grantor_kp=$($SIGN_BIN keygen ml-dsa-65)
grantor_pk=$(echo "$grantor_kp" | jq_ "print(d['public_key'])")
grantor_sk=$(echo "$grantor_kp" | jq_ "print(d['private_key'])")
grantor_did=$(echo "$grantor_kp" | jq_ "print(d['did'])")
info "Grantor PK: ${grantor_pk:0:24}... (1952 bytes)"
ok "Grantor: ${grantor_did:0:30}..."

attorney_kp=$($SIGN_BIN keygen ml-dsa-65)
attorney_pk=$(echo "$attorney_kp" | jq_ "print(d['public_key'])")
attorney_sk=$(echo "$attorney_kp" | jq_ "print(d['private_key'])")
attorney_did=$(echo "$attorney_kp" | jq_ "print(d['did'])")
info "Attorney PK: ${attorney_pk:0:24}... (1952 bytes)"
ok "Attorney: ${attorney_did:0:30}..."

# ── 3. Register DIDs ────────────────────────────────────────
step "Registering identities"
now=$(date +%s)

curl -sf -X POST "$API/store/identities" \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$grantor_did\",\"public_key\":\"$grantor_pk\",\"created_at\":$now,\"updated_at\":$now,\"status\":\"active\"}" >/dev/null \
  || fail "Failed to register grantor"
ok "Grantor registered"

curl -sf -X POST "$API/store/identities" \
  -H "Content-Type: application/json" \
  -d "{\"did\":\"$attorney_did\",\"public_key\":\"$attorney_pk\",\"created_at\":$now,\"updated_at\":$now,\"status\":\"active\"}" >/dev/null \
  || fail "Failed to register attorney"
ok "Attorney registered"

# ── 4. Deploy Power of Attorney (FEA required) ──────────────
step "Deploying Power of Attorney (FEA / ML-DSA-65 + biometric)"

deploy_body=$(python3 -c "
import json
print(json.dumps({
    'type': 'power_of_attorney',
    'parties': [
        {'role': 'grantor',  'did': '$grantor_did',  'signature_level': 'advanced'},
        {'role': 'attorney', 'did': '$attorney_did', 'signature_level': 'advanced'}
    ],
    'payload': {
        'scope': 'Full financial management',
        'jurisdiction': 'Chile',
        'effective_date': '2026-08-18',
        'expiry_date': '2027-08-18'
    },
    'require_notarization': True,
    'deadline_secs': 172800
}))
")

deploy_resp=$(curl -sf -X POST "$API/lexchain/deploy" \
  -H "Content-Type: application/json" \
  -d "$deploy_body") || fail "Deploy failed"

contract_id=$(echo "$deploy_resp" | jq_ "print(d['data']['id'])")
content_hash=$(echo "$deploy_resp" | jq_ "print(d['data']['content_hash'])")
state=$(echo "$deploy_resp" | jq_ "print(d['data']['state'])")

ok "Contract: $contract_id"
ok "Hash:     $content_hash"
ok "State:    $state"
info "Deadline: 48 hours"
info "Notarization: required"

[ "$state" = "pending_signatures" ] || fail "Expected pending_signatures"

# ── 5. Grantor signs (FEA / ML-DSA-65 + biometric) ──────────
step "Grantor signs (FEA / ML-DSA-65 + fingerprint biometric)"

# Simulate biometric capture — SHA-256 commitment of template
bio_commitment=$(python3 -c "
import hashlib
template = b'grantor-fingerprint-template-2026-08-18'
print(hashlib.sha256(template).hexdigest())
")
info "Biometric commitment: ${bio_commitment:0:24}..."

# Compute biometrics hash (same as engine: SHA-256 of sorted commitments joined by ':')
bio_hash=$(python3 -c "
import hashlib
print(hashlib.sha256('$bio_commitment'.encode()).hexdigest())
")

# FEA payload: fea:{did}:{content_hash}:{bio_hash}
grantor_payload="fea:${grantor_did}:${content_hash}:${bio_hash}"
info "Signing payload: ${grantor_payload:0:40}..."

grantor_sig=$($SIGN_BIN sign ml-dsa-65 "$grantor_sk" "$grantor_payload" | jq_ "print(d['signature'])")
info "Signature: ${grantor_sig:0:24}... (3309 bytes)"

sign_grantor_body=$(python3 -c "
import json
print(json.dumps({
    'did': '$grantor_did',
    'signature': '$grantor_sig',
    'public_key': '$grantor_pk',
    'biometric_evidence': [{
        'evidence_type': 'fingerprint',
        'commitment': '$bio_commitment',
        'captured_at': $now,
        'capture_device': 'BiometricScanner-v3'
    }]
}))
")

forged_body=$(echo "$sign_grantor_body" | python3 -c "
import sys, json
body = json.load(sys.stdin)
body['public_key'] = '$attorney_pk'
body['signature'] = '$($SIGN_BIN sign ml-dsa-65 "$attorney_sk" "$grantor_payload" | jq_ "print(d['signature'])")'
print(json.dumps(body))
")
forged_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/lexchain/$contract_id/sign" \
  -H "Content-Type: application/json" -d "$forged_body")
[ "$forged_code" = "400" ] || fail "Attorney impersonating grantor not rejected (HTTP $forged_code)"
ok "Attorney signing as grantor with own key rejected (HTTP $forged_code)"

sign_grantor_resp=$(curl -sf -X POST "$API/lexchain/$contract_id/sign" \
  -H "Content-Type: application/json" \
  -d "$sign_grantor_body") || fail "Grantor sign failed: $(curl -s -X POST "$API/lexchain/$contract_id/sign" -H "Content-Type: application/json" -d "$sign_grantor_body")"

state_after=$(echo "$sign_grantor_resp" | jq_ "print(d['data']['state'])")
ok "Grantor signed → state: $state_after"
[ "$state_after" = "pending_signatures" ] || fail "Expected pending_signatures"

# ── 6. Attorney signs (FEA / ML-DSA-65 + biometric) ─────────
step "Attorney signs (FEA / ML-DSA-65 + facial biometric)"

atty_bio=$(python3 -c "
import hashlib
template = b'attorney-facial-scan-2026-08-18'
print(hashlib.sha256(template).hexdigest())
")
info "Biometric commitment: ${atty_bio:0:24}..."

atty_bio_hash=$(python3 -c "
import hashlib
print(hashlib.sha256('$atty_bio'.encode()).hexdigest())
")

attorney_payload="fea:${attorney_did}:${content_hash}:${atty_bio_hash}"
attorney_sig=$($SIGN_BIN sign ml-dsa-65 "$attorney_sk" "$attorney_payload" | jq_ "print(d['signature'])")
info "Signature: ${attorney_sig:0:24}... (3309 bytes)"

sign_atty_body=$(python3 -c "
import json
print(json.dumps({
    'did': '$attorney_did',
    'signature': '$attorney_sig',
    'public_key': '$attorney_pk',
    'biometric_evidence': [{
        'evidence_type': 'facial_recognition',
        'commitment': '$atty_bio',
        'captured_at': $now,
        'capture_device': 'FaceID-Module-v2'
    }]
}))
")

sign_atty_resp=$(curl -sf -X POST "$API/lexchain/$contract_id/sign" \
  -H "Content-Type: application/json" \
  -d "$sign_atty_body") || fail "Attorney sign failed: $(curl -s -X POST "$API/lexchain/$contract_id/sign" -H "Content-Type: application/json" -d "$sign_atty_body")"

final_state=$(echo "$sign_atty_resp" | jq_ "print(d['data']['state'])")
ok "Attorney signed → state: $final_state"

case "$final_state" in
  notarized)   ok "Contract notarized with TSA timestamp (RFC 3161)" ;;
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
print(f'  Type:      {c[\"definition\"].get(\"type\", \"?\")}')
print(f'  State:     {c[\"state\"]}')
print(f'  Parties:   {len(c[\"parties\"])}')
for p in c['parties']:
    env = p.get('envelope') or {}
    algo = env.get('signature_algorithm', '—')
    bio = len(env.get('biometric_evidence', []))
    print(f'    {p[\"role\"]:12} {p[\"did\"][:30]}... algo={algo}  biometrics={bio}')
if c.get('tsa_token'):
    t = c['tsa_token']['tst_info']
    print(f'  TSA:       serial={t[\"serial_number\"]}  time={t[\"gen_time\"]}')
    print(f'  TSA algo:  {c[\"tsa_token\"].get(\"signature_algorithm\", \"?\")}')
print(f'  Hash:      {c[\"content_hash\"][:16]}...')
print(f'  Deadline:  {c[\"definition\"].get(\"deadline_secs\", \"none\")}s')
"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${G}${B}FEA end-to-end complete.${N}"
echo -e "Contract $contract_id signed by both parties with:"
echo -e "  • ML-DSA-65 (FIPS 204) — post-quantum lattice-based signatures"
echo -e "  • Biometric evidence (fingerprint + facial recognition)"
echo -e "  • Advanced Electronic Signature (FEA) — Chile Ley 19.799 / EU eIDAS"
echo ""
echo -e "This is a legally binding digital power of attorney with PQC cryptographic proof."
