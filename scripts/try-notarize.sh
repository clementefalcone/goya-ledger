#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Goya notarization end-to-end check (FES + FEA)
#
# Registers a DID, notarizes a document with FES, signs another
# with FEA (node ML-DSA-65 + biometric + signer proof), verifies
# both, and checks that impersonation attempts are rejected.
#
# Usage:
#   ./scripts/try-notarize.sh                    # default: localhost:8080
#   ./scripts/try-notarize.sh http://127.0.0.1:8080
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

G='\033[0;32m'; R='\033[0;31m'; B='\033[1m'; N='\033[0m'
ok()   { echo -e "${G}✓${N} $1"; }
fail() { echo -e "${R}✗${N} $1"; exit 1; }
step() { echo -e "\n${B}── $1${N}"; }
field() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
sha256() { python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$1"; }
ed_sign() { $SIGN_BIN sign ed25519 "$1" "$2" | field "['signature']"; }

post() {
  curl -s -o /tmp/goya-notarize-resp.json -w "%{http_code}" -X POST "$API$1" \
    -H "Content-Type: application/json" -d "$2"
}

step "Health check"
curl -sf "$API/health" >/dev/null 2>&1 || fail "Node unreachable at $NODE"
ok "Node alive at $NODE"

step "Creating identities (DID = SHA3-512 of the public key)"
alice=$($SIGN_BIN keygen ed25519)
alice_did=$(echo "$alice" | field "['did']")
alice_pk=$(echo "$alice" | field "['public_key']")
alice_sk=$(echo "$alice" | field "['private_key']")
mallory=$($SIGN_BIN keygen ed25519)
mallory_pk=$(echo "$mallory" | field "['public_key']")
mallory_sk=$(echo "$mallory" | field "['private_key']")
ok "Alice:   ${alice_did:0:30}..."

step "FES: Alice notarizes a document"
fes_hash=$(sha256 "contrato-fes-$(date +%s)-$RANDOM")
fes_sig=$(ed_sign "$alice_sk" "notarize:${alice_did}:${fes_hash}")
code=$(post /notarize "{\"content_hash\":\"$fes_hash\",\"signer\":\"$alice_did\",\"public_key\":\"$alice_pk\",\"signature\":\"$fes_sig\"}")
[ "$code" = "201" ] || fail "FES notarize returned HTTP $code: $(cat /tmp/goya-notarize-resp.json)"
ok "Notarized (HTTP $code)"

step "FES: Mallory notarizes under Alice's DID with her own key"
forged_hash=$(sha256 "forged-$(date +%s)-$RANDOM")
forged_sig=$(ed_sign "$mallory_sk" "notarize:${alice_did}:${forged_hash}")
code=$(post /notarize "{\"content_hash\":\"$forged_hash\",\"signer\":\"$alice_did\",\"public_key\":\"$mallory_pk\",\"signature\":\"$forged_sig\"}")
[ "$code" = "401" ] || fail "Impersonation not rejected (HTTP $code)"
ok "Rejected (HTTP $code)"

step "FES: verify Alice's document"
verified=$(curl -sf "$API/notarize/verify/$fes_hash" | field "['data']['verified']")
[ "$verified" = "True" ] || fail "Expected verified=true, got $verified"
ok "verified: true"

step "FEA: Alice signs with node ML-DSA-65 + biometric + signer proof"
fea_hash=$(sha256 "contrato-fea-$(date +%s)-$RANDOM")
commitment=$(sha256 "alice-fingerprint-template")
bio_hash=$(sha256 "$commitment")
fea_payload="notarize_fea:${alice_did}:${fea_hash}:${bio_hash}"
proof_sig=$(ed_sign "$alice_sk" "$fea_payload")
now=$(date +%s)
evidence="[{\"evidence_type\":\"fingerprint\",\"commitment\":\"$commitment\",\"captured_at\":$now,\"capture_device\":\"scanner-e2e\"}]"
proof="{\"public_key\":\"$alice_pk\",\"signature\":\"$proof_sig\"}"

code=$(post /sign/fea "{\"content_hash\":\"$fea_hash\",\"signer\":\"$alice_did\",\"biometric_evidence\":$evidence,\"signer_proof\":$proof}")
[ "$code" = "200" ] || [ "$code" = "201" ] || fail "sign/fea returned HTTP $code: $(cat /tmp/goya-notarize-resp.json)"
node_sig=$(field "['data']['signature']" < /tmp/goya-notarize-resp.json)
node_pk=$(field "['data']['public_key']" < /tmp/goya-notarize-resp.json)
ok "Node signed with ML-DSA-65 (HTTP $code, signature ${#node_sig} hex chars)"

code=$(post /notarize "{\"content_hash\":\"$fea_hash\",\"signer\":\"$alice_did\",\"public_key\":\"$node_pk\",\"signature\":\"$node_sig\",\"signature_level\":\"advanced\",\"signature_algorithm\":\"MlDsa65\",\"biometric_evidence\":$evidence,\"signer_proof\":$proof}")
[ "$code" = "201" ] || fail "FEA notarize returned HTTP $code: $(cat /tmp/goya-notarize-resp.json)"
ok "FEA notarized (HTTP $code)"

step "FEA: Mallory requests an FEA signature for Alice with her own proof"
mallory_proof_sig=$(ed_sign "$mallory_sk" "$fea_payload")
code=$(post /sign/fea "{\"content_hash\":\"$fea_hash\",\"signer\":\"$alice_did\",\"biometric_evidence\":$evidence,\"signer_proof\":{\"public_key\":\"$mallory_pk\",\"signature\":\"$mallory_proof_sig\"}}")
[ "$code" = "401" ] || fail "FEA impersonation not rejected (HTTP $code)"
ok "Rejected (HTTP $code)"

step "FEA: verify Alice's document"
verified=$(curl -sf "$API/notarize/verify/$fea_hash" | field "['data']['verified']")
[ "$verified" = "True" ] || fail "Expected verified=true, got $verified"
ok "verified: true"

rm -f /tmp/goya-notarize-resp.json
echo ""
echo -e "${G}${B}Notarization end-to-end complete.${N}"
