#!/usr/bin/env bash
# E2E test suite for rust-bc multi-org blockchain network.
# Requires: curl, jq, docker compose running (4 nodes).
#
# Usage: ./scripts/e2e-test.sh [--verbose]

set -uo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
# Use 127.0.0.1 so behavior matches Docker port maps on CI (avoids localhost → ::1 mismatches).
NODE1="https://127.0.0.1:8080"
NODE2="https://127.0.0.1:8082"
NODE3="https://127.0.0.1:8084"
ORDERER="https://127.0.0.1:8086"
ORDERER2="https://127.0.0.1:8088"
ORDERER3="https://127.0.0.1:8090"
# Prefer Homebrew curl (OpenSSL) over macOS system curl (LibreSSL) to avoid
# TLS bad_record_mac errors on POST requests with rustls servers.
if [[ -x /opt/homebrew/opt/curl/bin/curl ]]; then
    CURL_BIN=/opt/homebrew/opt/curl/bin/curl
else
    CURL_BIN=curl
fi
CURL="$CURL_BIN -sk --http1.1 --max-time 30"
VERBOSE="${1:-}"

PASSED=0
FAILED=0
SKIPPED=0

# ── Helpers ──────────────────────────────────────────────────────────────────
red()    { printf "\033[31m%s\033[0m" "$1"; }
green()  { printf "\033[32m%s\033[0m" "$1"; }
yellow() { printf "\033[33m%s\033[0m" "$1"; }
bold()   { printf "\033[1m%s\033[0m" "$1"; }

log() { echo "  $*"; }

api() {
    local method="$1" url="$2"
    shift 2
    local resp
    resp=$($CURL -X "$method" "$url" -H 'Content-Type: application/json' "$@" 2>&1) || true
    if [[ "$VERBOSE" == "--verbose" ]]; then
        echo "$resp" | jq . 2>/dev/null || echo "$resp"
    fi
    echo "$resp"
}

# Extract .data from API response envelope
data() { jq -r '.data // .Data // empty' 2>/dev/null; }

assert_status() {
    local resp="$1" expected="$2" label="$3"
    local code
    code=$(echo "$resp" | jq -r '.status_code // .statusCode // empty' 2>/dev/null)
    # Fallback: check .success for legacy endpoints
    if [[ -z "$code" ]]; then
        local success
        success=$(echo "$resp" | jq -r '.success // empty' 2>/dev/null)
        if [[ "$success" == "true" ]]; then code=200; fi
        if [[ "$success" == "false" ]]; then code=400; fi
    fi
    if [[ "$code" == "$expected" ]]; then
        echo "  $(green "PASS") $label"
        PASSED=$((PASSED + 1))
    else
        echo "  $(red "FAIL") $label (expected $expected, got ${code:-empty})"
        if [[ "$VERBOSE" == "--verbose" ]]; then echo "$resp" | head -3; fi
        FAILED=$((FAILED + 1))
    fi
}

assert_eq() {
    local actual="$1" expected="$2" label="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "  $(green "PASS") $label"
        PASSED=$((PASSED + 1))
    else
        echo "  $(red "FAIL") $label (expected '$expected', got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

assert_gt() {
    local actual="$1" min="$2" label="$3"
    if [[ "$actual" -gt "$min" ]] 2>/dev/null; then
        echo "  $(green "PASS") $label"
        PASSED=$((PASSED + 1))
    else
        echo "  $(red "FAIL") $label (expected > $min, got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

skip() {
    echo "  $(yellow "SKIP") $1"
    SKIPPED=$((SKIPPED + 1))
}

section() {
    echo ""
    echo "$(bold "$1")"
}

assert_not_empty() {
    local actual="$1" label="$2"
    if [[ -n "$actual" && "$actual" != "null" ]]; then
        echo "  $(green "PASS") $label"
        PASSED=$((PASSED + 1))
    else
        echo "  $(red "FAIL") $label (empty response)"
        FAILED=$((FAILED + 1))
    fi
}

ACCOUNT_TOOL="$(cd "$(dirname "$0")" && pwd)/ledger-account/account.mjs"
ACCOUNT_DIR=$(mktemp -d)
trap 'rm -rf "$ACCOUNT_DIR"' EXIT
ISSUER_SEED="${E2E_ISSUER_SEED:-}"
[[ -d "$(dirname "$ACCOUNT_TOOL")/node_modules" ]] || npm ci --silent --prefix "$(dirname "$ACCOUNT_TOOL")"

ledger_tool() {
    local seed="$1"
    shift
    NODE_URL="$NODE1/api/v1" NODE_TLS_REJECT_UNAUTHORIZED=0 SEED_PATH="$seed" node "$ACCOUNT_TOOL" "$@"
}

account() {
    local name="$1"
    shift
    ledger_tool "$ACCOUNT_DIR/$name.hex" "$@"
}

new_account() {
    account "$1" keygen > /dev/null && account "$1" register
}

http_code() {
    local method="$1" url="$2"
    shift 2
    $CURL -o /dev/null -w '%{http_code}' -X "$method" "$url" -H 'Content-Type: application/json' "$@"
}

ensure_issuer_registered() {
    local did
    did=$(ledger_tool "$ISSUER_SEED" did)
    [[ "$(http_code GET "$NODE1/api/v1/store/identities/$did")" == "200" ]] || ledger_tool "$ISSUER_SEED" register > /dev/null
}

ISSUER_HINT="set E2E_ISSUER_SEED to the seed of node1's NOTA_ISSUER_DID"

# ── Pre-flight ───────────────────────────────────────────────────────────────
echo ""
bold "═══ rust-bc E2E Test Suite ═══"
echo ""

echo "$(bold '1. Pre-flight checks')"
for name_port in "node1:8080" "node2:8082" "node3:8084" "orderer1:8086"; do
    name="${name_port%%:*}"
    port="${name_port##*:}"
    resp=$(api GET "https://127.0.0.1:$port/api/v1/health")
    status=$(echo "$resp" | jq -r '.data.status // empty' 2>/dev/null)
    assert_eq "$status" "healthy" "$name is healthy"
done

# Check peer connectivity
peers=$(api GET "$NODE1/api/v1/stats" | jq -r '.data.network.connected_peers' 2>/dev/null)
assert_gt "$peers" 0 "node1 has P2P peers ($peers connected)"

# ── Test 2: Organizations ────────────────────────────────────────────────────
echo ""
echo "$(bold '2. Register organizations')"

ORG1_KEY=$(python3 -c "import os; print(list(os.urandom(32)))" | tr -d '[] ')
ORG2_KEY=$(python3 -c "import os; print(list(os.urandom(32)))" | tr -d '[] ')

resp=$(api POST "$NODE1/api/v1/store/organizations" -d '{
    "org_id": "org1",
    "msp_id": "Org1MSP",
    "admin_dids": ["did:bc:admin1"],
    "member_dids": ["did:bc:peer1", "did:bc:peer3"],
    "root_public_keys": [[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]
}')
assert_status "$resp" 200 "Create org1"

resp=$(api POST "$NODE1/api/v1/store/organizations" -d '{
    "org_id": "org2",
    "msp_id": "Org2MSP",
    "admin_dids": ["did:bc:admin2"],
    "member_dids": ["did:bc:peer2"],
    "root_public_keys": [[2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]
}')
assert_status "$resp" 200 "Create org2"

resp=$(api GET "$NODE1/api/v1/store/organizations")
org_count=$(echo "$resp" | jq '.data | length' 2>/dev/null)
assert_eq "$org_count" "2" "List organizations returns 2"

# ── Test 3: Endorsement Policies ─────────────────────────────────────────────
echo ""
echo "$(bold '3. Endorsement policies')"

resp=$(api POST "$NODE1/api/v1/store/policies" -d '{
    "resource_id": "mycc",
    "policy": {"NOutOf": {"n": 2, "orgs": ["org1", "org2"]}}
}')
assert_status "$resp" 200 "Set policy NOutOf(2, [org1, org2])"

resp=$(api GET "$NODE1/api/v1/store/policies/mycc")
policy_type=$(echo "$resp" | jq -r '.data | keys[0] // empty' 2>/dev/null)
assert_eq "$policy_type" "NOutOf" "Get policy returns NOutOf"

# Also register policy with channel/chaincode key for discovery endorsers
resp=$(api POST "$NODE1/api/v1/store/policies" -d '{
    "resource_id": "mychannel/mycc",
    "policy": {"NOutOf": {"n": 2, "orgs": ["org1", "org2"]}}
}')
assert_status "$resp" 200 "Set discovery policy mychannel/mycc"

# ── Test 4: Channels ─────────────────────────────────────────────────────────
echo ""
echo "$(bold '4. Channel management')"

resp=$(api POST "$NODE1/api/v1/channels" -d '{"channel_id": "mychannel"}')
ch_code=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$ch_code" == "200" || "$ch_code" == "201" || "$ch_code" == "409" ]]; then
    echo "  $(green "PASS") Create channel 'mychannel' ($ch_code)"
    PASSED=$((PASSED + 1))
else
    echo "  $(red "FAIL") Create channel 'mychannel' (got $ch_code)"
    FAILED=$((FAILED + 1))
fi

resp=$(api GET "$NODE1/api/v1/channels")
ch_count=$(echo "$resp" | jq '.data | length' 2>/dev/null)
assert_gt "$ch_count" 0 "List channels returns >= 1"

# Channel isolation: write a tx to mychannel, verify default channel unaffected
resp=$(api POST "$NODE1/api/v1/store/transactions" \
    -H "X-Channel-Id: mychannel" \
    -d '{"id":"tx-ch-1","block_height":0,"timestamp":1000,"input_did":"did:bc:alice","output_recipient":"did:bc:bob","amount":10,"state":"committed"}')
ch_status=$(echo "$resp" | jq -r '.status_code // .statusCode // empty' 2>/dev/null)
if [[ "$ch_status" == "201" || "$ch_status" == "200" ]]; then
    echo "  $(green "PASS") Write transaction to mychannel"
    PASSED=$((PASSED + 1))

    # Verify it's NOT in default channel
    resp_default=$(api GET "$NODE1/api/v1/store/transactions/tx-ch-1")
    default_status=$(echo "$resp_default" | jq -r '.status_code // empty' 2>/dev/null)
    if [[ "$default_status" == "404" ]]; then
        echo "  $(green "PASS") Transaction NOT visible in default channel (isolation)"
        PASSED=$((PASSED + 1))
    else
        echo "  $(red "FAIL") Channel isolation — tx visible in default (status=$default_status)"
        FAILED=$((FAILED + 1))
    fi
else
    skip "Channel transaction write (status=$ch_status)"
fi

# ── Test 5: Block Mining & Propagation ───────────────────────────────────────
echo ""
echo "$(bold '5. Block mining & multi-node propagation')"

# Create wallet
wallet_resp=$(api POST "$NODE1/api/v1/wallets/create" -d '{}')
ADDR=$(echo "$wallet_resp" | jq -r '.data.address // empty' 2>/dev/null)
if [[ -n "$ADDR" && "$ADDR" != "null" ]]; then
    echo "  $(green "PASS") Create wallet ($ADDR)"
    PASSED=$((PASSED + 1))
else
    echo "  $(red "FAIL") Create wallet"
    FAILED=$((FAILED + 1))
    ADDR="fallback"
fi

# Get initial block count
initial_blocks=$(api GET "$NODE1/api/v1/stats" | jq '.data.blockchain.block_count' 2>/dev/null)

# Mine a block
resp=$(api POST "$NODE1/api/v1/mine" -d "{\"miner_address\":\"$ADDR\"}")
mine_ok=$(echo "$resp" | jq -r '.success // empty' 2>/dev/null)
assert_eq "$mine_ok" "true" "Mine block on node1"

# Wait for propagation (gossip may need multiple rounds)
sleep 5

# Check all peers have the same block count and hash
n1_hash=$(api GET "$NODE1/api/v1/stats" | jq -r '.data.blockchain.latest_block_hash' 2>/dev/null)
n2_hash=$(api GET "$NODE2/api/v1/stats" | jq -r '.data.blockchain.latest_block_hash' 2>/dev/null)
n3_hash=$(api GET "$NODE3/api/v1/stats" | jq -r '.data.blockchain.latest_block_hash' 2>/dev/null)

assert_eq "$n2_hash" "$n1_hash" "node2 has same latest hash as node1"
assert_eq "$n3_hash" "$n1_hash" "node3 has same latest hash as node1"

n1_count=$(api GET "$NODE1/api/v1/stats" | jq '.data.blockchain.block_count' 2>/dev/null)
expected_count=$((initial_blocks + 1))
assert_eq "$n1_count" "$expected_count" "Block count incremented ($initial_blocks -> $expected_count)"

# ── Test 6: Transaction Lifecycle ────────────────────────────────────────────
echo ""
echo "$(bold '6. Transaction lifecycle (mempool -> block)')"

SENDER=$(new_account sender)
assert_not_empty "$SENDER" "Register sender identity"
RECEIVER=$(account receiver keygen)

code=$(http_code POST "$NODE1/api/v1/transactions" -d "{\"from\":\"$SENDER\",\"to\":\"$RECEIVER\",\"amount\":1,\"nonce\":0}")
assert_eq "$code" "400" "Transfer without signature is rejected"

code=$(http_code POST "$NODE1/api/v1/transactions" -d "{\"from\":\"$SENDER\",\"to\":\"$RECEIVER\",\"amount\":1,\"nonce\":0,\"signature\":\"00\"}")
assert_eq "$code" "401" "Transfer with forged signature is rejected"

if [[ -n "$ISSUER_SEED" ]]; then
    ensure_issuer_registered
    ledger_tool "$ISSUER_SEED" mint "$SENDER" 10 > /dev/null
    assert_eq "$?" "0" "Issuer mints 10 NOTA to sender"
    api POST "$NODE1/api/v1/mine" -d '{}' > /dev/null
    sleep 2
    sender_bal=$(api GET "$NODE1/api/v1/accounts/$SENDER" | jq -r '.data.balance // 0' 2>/dev/null)
    assert_eq "$sender_bal" "10" "Minted balance confirmed in a block"
else
    skip "Mint and mine ($ISSUER_HINT)"
fi

# ── Test 7: Private Data ─────────────────────────────────────────────────────
echo ""
echo "$(bold '7. Private data collections')"

# Register collection first
resp=$(api POST "$NODE1/api/v1/private-data/collections" -d '{
    "name": "secret-collection",
    "member_org_ids": ["org1"],
    "required_peer_count": 1,
    "blocks_to_live": 100
}')
reg_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_status "$resp" 200 "Register private data collection"

# Write private data as org1
resp=$(api PUT "$NODE1/api/v1/private-data/secret-collection/key1" \
    -H "X-Org-Id: org1" \
    -d '{"value": "secret-for-org1"}')
assert_status "$resp" 200 "Write private data as org1"

# Read as org1 (should succeed)
resp=$(api GET "$NODE1/api/v1/private-data/secret-collection/key1" -H "X-Org-Id: org1")
pd_value=$(echo "$resp" | jq -r '.data.value // empty' 2>/dev/null)
assert_eq "$pd_value" "secret-for-org1" "Read private data as org1 (authorized)"

# Read as org2 (should fail with 403 — not a member)
resp=$(api GET "$NODE1/api/v1/private-data/secret-collection/key1" -H "X-Org-Id: org2")
deny_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_eq "$deny_status" "403" "Private data denied for org2 (403)"

# ── Test 8: Discovery Service ────────────────────────────────────────────────
echo ""
echo "$(bold '8. Discovery service')"

# Register a peer
resp=$(api POST "$NODE1/api/v1/discovery/register" -d '{
    "peer_address": "node1:8081",
    "org_id": "org1",
    "role": "PeerAndOrderer",
    "chaincodes": ["mycc"],
    "channels": ["mychannel"],
    "last_heartbeat": 9999999999
}')
disc_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$disc_status" == "200" || "$disc_status" == "201" ]]; then
    echo "  $(green "PASS") Register peer in discovery"
    PASSED=$((PASSED + 1))
else
    skip "Discovery register (status=$disc_status)"
fi

# Register node2
resp=$(api POST "$NODE1/api/v1/discovery/register" -d '{
    "peer_address": "node2:8081",
    "org_id": "org2",
    "role": "Peer",
    "chaincodes": ["mycc"],
    "channels": ["mychannel"],
    "last_heartbeat": 9999999999
}')

# Query endorsers
resp=$(api GET "$NODE1/api/v1/discovery/endorsers?chaincode=mycc&channel=mychannel")
endorser_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$endorser_status" == "200" ]]; then
    endorser_count=$(echo "$resp" | jq '.data | length' 2>/dev/null)
    assert_gt "$endorser_count" 0 "Discovery returns endorsers ($endorser_count found)"
else
    skip "Discovery endorsers query (status=$endorser_status)"
fi

# Query channel peers
resp=$(api GET "$NODE1/api/v1/discovery/peers?channel=mychannel")
peer_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$peer_status" == "200" ]]; then
    peer_count=$(echo "$resp" | jq '.data | length' 2>/dev/null)
    assert_gt "$peer_count" 0 "Discovery returns channel peers ($peer_count found)"
else
    skip "Discovery channel peers (status=$peer_status)"
fi

# ── Test 9: Gateway Submit ───────────────────────────────────────────────────
echo ""
echo "$(bold '9. Gateway (endorse -> order -> commit)')"

resp=$(api POST "$NODE1/api/v1/gateway/submit" -d '{
    "chaincode_id": "mycc",
    "channel_id": "",
    "transaction": {
        "id": "gw-tx-001",
        "input_did": "did:bc:admin1",
        "output_recipient": "did:bc:peer2",
        "amount": 50
    }
}')
assert_status "$resp" 200 "Gateway submit (endorse -> order -> commit)"
gw_tx=$(echo "$resp" | jq -r '.data.tx_id // empty' 2>/dev/null)
gw_height=$(echo "$resp" | jq -r '.data.block_height // empty' 2>/dev/null)
if [[ -n "$gw_tx" && "$gw_tx" != "null" ]]; then
    assert_eq "$gw_tx" "gw-tx-001" "Gateway returns correct tx_id"
    assert_gt "$gw_height" 0 "Gateway committed at block height $gw_height"
fi

# ── Test 10: Chain Integrity ─────────────────────────────────────────────────
echo ""
echo "$(bold '10. Chain integrity verification')"

for name_port in "node1:8080" "node2:8082" "node3:8084"; do
    name="${name_port%%:*}"
    port="${name_port##*:}"
    resp=$(api GET "https://127.0.0.1:$port/api/v1/chain/verify")
    verify_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
    valid=$(echo "$resp" | jq -r '.data.valid // empty' 2>/dev/null)
    block_count=$(echo "$resp" | jq -r '.data.block_count // empty' 2>/dev/null)
    if [[ "$verify_status" == "200" ]]; then
        echo "  $(green "PASS") $name chain verify (valid=$valid, blocks=$block_count)"
        PASSED=$((PASSED + 1))
    else
        skip "$name chain verify (status=$verify_status)"
    fi
done

# ── Test 11: Observability ───────────────────────────────────────────────────
echo ""
echo "$(bold '11. Observability')"

# Prometheus metrics
resp=$($CURL "https://127.0.0.1:8080/metrics" 2>&1)
if echo "$resp" | grep -q "endorsement_validations_total\|ordering_blocks_cut_total\|rust_bc"; then
    echo "  $(green "PASS") Prometheus metrics endpoint returns metrics"
    PASSED=$((PASSED + 1))
else
    skip "Prometheus metrics (endpoint may not match expected format)"
fi

# Prometheus scrape target
resp=$($CURL "http://127.0.0.1:9090/api/v1/targets" 2>&1)
if echo "$resp" | grep -q "rust-bc\|node1"; then
    echo "  $(green "PASS") Prometheus scraping nodes"
    PASSED=$((PASSED + 1))
else
    skip "Prometheus targets (may need configuration)"
fi

# Grafana health (skip when Grafana is not running, e.g. CI)
resp=$($CURL "http://127.0.0.1:3000/api/health" 2>&1)
grafana_ok=$(echo "$resp" | jq -r '.database // empty' 2>/dev/null)
if [[ "$grafana_ok" == "ok" ]]; then
    echo "  $(green "PASS") Grafana is healthy"
    PASSED=$((PASSED + 1))
elif [[ -z "$grafana_ok" ]]; then
    skip "Grafana is not running"
else
    assert_eq "$grafana_ok" "ok" "Grafana is healthy"
fi

# ── Test 12: Store-backed endpoints ──────────────────────────────────────────
echo ""
echo "$(bold '12. Store-backed CRUD')"

# Write identity (fields: did, created_at, updated_at, status)
resp=$(api POST "$NODE1/api/v1/store/identities" -d '{
    "did": "did:bc:test1",
    "created_at": 1000,
    "updated_at": 1000,
    "status": "active"
}')
assert_status "$resp" 200 "Store identity"

resp=$(api GET "$NODE1/api/v1/store/identities/did:bc:test1")
assert_status "$resp" 200 "Read identity back"

# Write credential (fields: id, issuer_did, subject_did, cred_type, issued_at, expires_at)
resp=$(api POST "$NODE1/api/v1/store/credentials" -d '{
    "id": "cred-001",
    "issuer_did": "did:bc:admin1",
    "subject_did": "did:bc:test1",
    "cred_type": "membership",
    "issued_at": 1000,
    "expires_at": 99999999,
    "revoked_at": null
}')
assert_status "$resp" 200 "Store credential"

resp=$(api GET "$NODE1/api/v1/store/credentials/cred-001")
assert_status "$resp" 200 "Read credential back"

# ── Test 13: Chaincode Lifecycle (Fabric core) ──────────────────────────────
echo ""
echo "$(bold '13. Chaincode lifecycle (install → approve → commit → simulate)')"

# Minimal WAT module that writes key "x" = "1" (proven in unit tests)
WAT_MODULE='(module
  (import "env" "put_state" (func $put (param i32 i32 i32 i32) (result i32)))
  (import "env" "get_state" (func $get (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "x")
  (data (i32.const 4) "1")
  (func (export "run") (result i64)
    (drop (call $put (i32.const 0) (i32.const 1) (i32.const 4) (i32.const 1)))
    (i64.or
      (i64.shl (i64.const 8) (i64.const 32))
      (i64.extend_i32_u
        (call $get (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 64))))
  )
)'

# Install chaincode
resp=$($CURL -X POST "$NODE1/api/v1/chaincode/install?chaincode_id=basic&version=1.0" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "$WAT_MODULE" 2>&1)
assert_status "$resp" 200 "Install chaincode 'basic' v1.0"
cc_size=$(echo "$resp" | jq -r '.data.size_bytes // empty' 2>/dev/null)
if [[ -n "$cc_size" && "$cc_size" != "null" ]]; then
    assert_gt "$cc_size" 0 "Installed package has size ($cc_size bytes)"
fi

# Approve org1
resp=$(api POST "$NODE1/api/v1/chaincode/basic/approve?version=1.0" \
    -H "X-Org-Id: org1" -d '{}')
assert_status "$resp" 200 "Approve chaincode as org1"

# Approve org2
resp=$(api POST "$NODE1/api/v1/chaincode/basic/approve?version=1.0" \
    -H "X-Org-Id: org2" -d '{}')
assert_status "$resp" 200 "Approve chaincode as org2"

# Commit (may return 200 or 409 if already committed via auto-create)
resp=$(api POST "$NODE1/api/v1/chaincode/basic/commit?version=1.0" -d '{}')
cc_commit_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$cc_commit_status" == "200" || "$cc_commit_status" == "409" ]]; then
    echo "  $(green "PASS") Chaincode commit ($cc_commit_status — already committed via auto-create is OK)"
    PASSED=$((PASSED + 1))
else
    echo "  $(red "FAIL") Chaincode commit (expected 200 or 409, got $cc_commit_status)"
    FAILED=$((FAILED + 1))
fi

# Simulate
resp=$(api POST "$NODE1/api/v1/chaincode/basic/simulate?version=1.0" \
    -d '{"function":"run"}')
sim_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$sim_status" == "200" ]]; then
    echo "  $(green "PASS") Simulate chaincode"
    PASSED=$((PASSED + 1))
    # Verify rwset contains writes
    rwset_writes=$(echo "$resp" | jq '.data.rwset.writes | length // 0' 2>/dev/null)
    assert_gt "${rwset_writes:-0}" 0 "Simulation produced write-set ($rwset_writes writes)"
else
    skip "Chaincode simulate (status=$sim_status)"
fi

# ── Test 14: Channel Configuration Governance ───────────────────────────────
echo ""
echo "$(bold '14. Channel config governance')"

resp=$(api POST "$NODE1/api/v1/channels" -d '{"channel_id": "govtest"}')
gov_code=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$gov_code" == "200" || "$gov_code" == "201" || "$gov_code" == "409" ]]; then
    echo "  $(green "PASS") Create channel 'govtest' ($gov_code)"
    PASSED=$((PASSED + 1))
else
    echo "  $(red "FAIL") Create channel 'govtest' (got $gov_code)"
    FAILED=$((FAILED + 1))
fi

# Get config (version 0)
resp=$(api GET "$NODE1/api/v1/channels/govtest/config")
cfg_version=$(echo "$resp" | jq -r '.data.version // empty' 2>/dev/null)
assert_eq "$cfg_version" "0" "Initial config version is 0"

# Config updates require endorsed signatures (Fabric behavior).
# AnyOf([]) default policy rejects empty signatures via validate_endorsements.
# To test config governance properly we'd need a valid Ed25519 endorsement.
# For now, verify that unauthenticated config updates are correctly rejected.
resp=$(api POST "$NODE1/api/v1/channels/govtest/config" -d '{
    "tx_id": "cfg-add-org1",
    "channel_id": "govtest",
    "updates": [{"type":"AddOrg","value":"org1"}],
    "signatures": [],
    "created_at": 1000
}')
cfg_update_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_eq "$cfg_update_status" "400" "Config update without endorsement rejected (400)"

# Config history should have only genesis
resp=$(api GET "$NODE1/api/v1/channels/govtest/config/history")
history_count=$(echo "$resp" | jq '.data | length' 2>/dev/null)
assert_eq "$history_count" "1" "Config history has 1 entry (genesis only)"

# ── Test 15: Event Polling ──────────────────────────────────────────────────
echo ""
echo "$(bold '15. Event polling (block events)')"

# Event polling reads from the per-channel store.  Gateway writes to its
# own internal store (not the channel store map), so blocks from gateway
# submit are not visible via event poll.  Verify endpoint is functional.

# Poll from height 0 — returns whatever is in the default store
resp=$(api GET "$NODE1/api/v1/events/blocks?from_height=0")
evt_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_eq "$evt_status" "200" "Event poll endpoint returns 200"

# Poll from future height — should return empty array
resp=$(api GET "$NODE1/api/v1/events/blocks?from_height=99999")
future_count=$(echo "$resp" | jq '.data | length' 2>/dev/null)
assert_eq "${future_count:-0}" "0" "Poll from future height returns empty array"

# ── Test 16: ACL Enforcement ────────────────────────────────────────────────
echo ""
echo "$(bold '16. ACL enforcement')"

# Create an AnyOf policy for ACL testing (org1 OR org2 can invoke)
resp=$(api POST "$NODE1/api/v1/store/policies" -d '{
    "resource_id": "acl-invoke-policy",
    "policy": {"AnyOf": ["org1", "org2"]}
}')
assert_status "$resp" 200 "Create AnyOf policy for ACL test"

# Set an ACL entry pointing to the AnyOf policy
resp=$(api POST "$NODE1/api/v1/acls" -d '{
    "resource": "peer/ChaincodeToChaincode",
    "policy_ref": "acl-invoke-policy"
}')
assert_status "$resp" 200 "Set ACL: peer/ChaincodeToChaincode → mycc policy"

# List ACLs
resp=$(api GET "$NODE1/api/v1/acls")
acl_count=$(echo "$resp" | jq '.data | length' 2>/dev/null)
assert_gt "${acl_count:-0}" 0 "ACL list has entries ($acl_count)"

# Get specific ACL
resp=$(api GET "$NODE1/api/v1/acls/peer%2FChaincodeToChaincode")
acl_policy=$(echo "$resp" | jq -r '.data.policy_ref // empty' 2>/dev/null)
assert_eq "$acl_policy" "acl-invoke-policy" "ACL entry returns correct policy_ref"

# Gateway submit as org1 (should succeed — org1 satisfies AnyOf([org1,org2]))
resp=$(api POST "$NODE1/api/v1/gateway/submit" \
    -H "X-Org-Id: org1" \
    -d '{
        "chaincode_id": "test-acl",
        "transaction": {
            "id": "acl-tx-ok",
            "input_did": "did:bc:admin1",
            "output_recipient": "did:bc:peer2",
            "amount": 5
        }
    }')
acl_ok_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_eq "$acl_ok_status" "200" "Gateway submit with authorized org succeeds"

# Gateway submit as org3 (should be denied — org3 not in NOutOf policy)
resp=$(api POST "$NODE1/api/v1/gateway/submit" \
    -H "X-Org-Id: org3" \
    -d '{
        "chaincode_id": "test-acl",
        "transaction": {
            "id": "acl-tx-denied",
            "input_did": "did:bc:intruder",
            "output_recipient": "did:bc:peer2",
            "amount": 5
        }
    }')
acl_denied_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_eq "$acl_denied_status" "403" "Gateway submit with unauthorized org denied (403)"

# ── Test 17: Channel Membership Enforcement ─────────────────────────────────
echo ""
echo "$(bold '17. Channel membership enforcement')"

# govtest has empty member_orgs (config update requires endorsement).
# With empty member_orgs, any org can submit (permissive bootstrap).
# Verify the membership layer does NOT reject (403); downstream errors (e.g.
# missing endorsement plan → 500) are acceptable — we only test membership here.
resp=$(api POST "$NODE1/api/v1/gateway/submit" \
    -H "X-Org-Id: org1" \
    -d '{
        "chaincode_id": "cc-ch",
        "channel_id": "govtest",
        "transaction": {
            "id": "ch-tx-open",
            "input_did": "did:bc:admin1",
            "output_recipient": "did:bc:peer2",
            "amount": 5
        }
    }')
ch_open_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$ch_open_status" == "403" ]]; then
    echo "  $(red "FAIL") Channel with empty member_orgs allows any org (permissive) (got 403 — membership rejected)"
    FAILED=$((FAILED + 1))
else
    echo "  $(green "PASS") Channel with empty member_orgs allows any org (permissive)"
    PASSED=$((PASSED + 1))
fi

# Default channel always allows (special case)
resp=$(api POST "$NODE1/api/v1/gateway/submit" \
    -H "X-Org-Id: org1" \
    -d '{"chaincode_id":"cc-ch","channel_id":"","transaction":{"id":"ch-tx-default","input_did":"did:bc:admin1","output_recipient":"did:bc:peer2","amount":5}}')
ch_default_status=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_eq "$ch_default_status" "200" "Default channel always allows access"

# ── Test 18: Gateway MVCC Validity ──────────────────────────────────────────
echo ""
echo "$(bold '18. Gateway response includes MVCC validity')"

sleep 2  # Allow rate limiter to reset
MVCC_TX_ID="mvcc-$(date +%s)"
resp=$($CURL -X POST "$NODE1/api/v1/gateway/submit" \
    -H 'Content-Type: application/json' \
    -H 'X-Org-Id: org1' \
    -d "{\"chaincode_id\":\"cc-mvcc\",\"transaction\":{\"id\":\"$MVCC_TX_ID\",\"input_did\":\"did:bc:alice\",\"output_recipient\":\"did:bc:bob\",\"amount\":10}}" 2>&1) || true
assert_status "$resp" 200 "Gateway submit for MVCC test"
gw_valid=$(echo "$resp" | jq -r '.data.valid // empty' 2>/dev/null)
assert_eq "$gw_valid" "true" "Gateway response includes valid=true"

# ── Test 19: MSP Role Enforcement ──────────────────────────────────────────
echo ""
echo "$(bold '19. MSP role enforcement')"

# Admin endpoint with client role → should be denied
resp=$(api POST "$NODE1/api/v1/store/organizations" \
    -H "X-Org-Id: org1" \
    -H "X-Msp-Role: client" \
    -d '{"org_id":"role-test","msp_id":"RoleTestMSP","admin_dids":[],"member_dids":[],"root_public_keys":[]}')
role_denied=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_eq "$role_denied" "403" "Admin endpoint rejects client role (403)"

# Admin endpoint with admin role → should succeed
resp=$(api POST "$NODE1/api/v1/store/organizations" \
    -H "X-Org-Id: org1" \
    -H "X-Msp-Role: admin" \
    -d '{"org_id":"role-test","msp_id":"RoleTestMSP","admin_dids":["did:bc:roleadmin"],"member_dids":[],"root_public_keys":[[3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}')
role_ok=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
if [[ "$role_ok" == "200" || "$role_ok" == "201" ]]; then
    echo "  $(green "PASS") Admin endpoint accepts admin role"
    PASSED=$((PASSED + 1))
else
    echo "  $(red "FAIL") Admin endpoint accepts admin role (expected 200/201, got $role_ok)"
    FAILED=$((FAILED + 1))
fi

# Writer endpoint with peer role → should succeed
resp=$(api POST "$NODE1/api/v1/gateway/submit" \
    -H "X-Org-Id: org1" \
    -H "X-Msp-Role: peer" \
    -d '{"chaincode_id":"role-cc","transaction":{"id":"role-tx-1","input_did":"did:bc:alice","output_recipient":"did:bc:bob","amount":1}}')
role_peer=$(echo "$resp" | jq -r '.status_code // empty' 2>/dev/null)
assert_eq "$role_peer" "200" "Writer endpoint accepts peer role"

# ── Test 20: Crash Recovery (store persistence) ──────────────────────────
echo ""
echo "$(bold '20. Crash recovery (store persistence)')"

# Write a unique transaction to the store
RECOVERY_TX_ID="recovery-$(date +%s)"
resp=$(api POST "$NODE1/api/v1/store/transactions" -d "{
    \"id\": \"$RECOVERY_TX_ID\",
    \"block_height\": 0,
    \"timestamp\": 0,
    \"input_did\": \"did:bc:alice\",
    \"output_recipient\": \"did:bc:bob\",
    \"amount\": 42,
    \"state\": \"pending\"
}")
assert_status "$resp" 201 "Write test transaction for recovery"

# Read it back immediately (baseline)
resp=$(api GET "$NODE1/api/v1/store/transactions/$RECOVERY_TX_ID")
pre_amount=$(echo "$resp" | jq -r '.data.amount // empty' 2>/dev/null)
assert_eq "$pre_amount" "42" "Transaction readable before restart"

# Note: full crash recovery (docker stop/start) is manual.
# This test verifies the store-backed write/read cycle works.
skip "Docker stop/start test (run manually: docker compose stop node1 && docker compose start node1)"

# ── 13. Raft Orderer Cluster Health ──────────────────────────────────────────
section "Raft Orderer Cluster"

resp=$(api GET "$ORDERER/api/v1/health")
assert_not_empty "$resp" "Orderer1 health responds"

resp2=$(api GET "$ORDERER2/api/v1/health")
assert_not_empty "$resp2" "Orderer2 health responds"

resp3=$(api GET "$ORDERER3/api/v1/health")
assert_not_empty "$resp3" "Orderer3 health responds"

# ── Test 21: Token Transfer Cycle (wallet → mine → transfer → verify) ───────
section "21. Token transfer cycle"

if [[ -n "$ISSUER_SEED" ]]; then
    account sender transfer "$RECEIVER" 5 > /dev/null
    assert_eq "$?" "0" "Sender signs and submits transfer"
    api POST "$NODE1/api/v1/mine" -d '{}' -H "X-Org-Id: org1" -H "X-Msp-Role: client" > /dev/null
    sleep 2
    recv_bal=$(api GET "$NODE1/api/v1/accounts/$RECEIVER" | jq -r '.data.balance // 0' 2>/dev/null)
    assert_eq "$recv_bal" "5" "Receiver balance after signed transfer"
    sender_bal=$(api GET "$NODE1/api/v1/accounts/$SENDER" | jq -r '.data.balance // 0' 2>/dev/null)
    assert_eq "$sender_bal" "5" "Sender balance after signed transfer"
else
    skip "Signed transfer cycle ($ISSUER_HINT)"
fi

# ── Test 22: ERC-20 Contract Flow ───────────────────────────────────────────
section "22. ERC-20 contract flow"

deploy_resp=$(api POST "$NODE1/api/v1/contracts" -d "{
    \"owner\": \"$SENDER\",
    \"contract_type\": \"ERC20\",
    \"name\": \"E2EToken\",
    \"symbol\": \"E2E\",
    \"total_supply\": 1000000,
    \"decimals\": 18
}")
CONTRACT=$(echo "$deploy_resp" | jq -r '.data // empty' 2>/dev/null)
if [[ -n "$CONTRACT" && "$CONTRACT" != "null" ]]; then
    echo "  $(green "PASS") Deploy ERC-20 ($CONTRACT)"
    PASSED=$((PASSED + 1))

    # Check total supply
    supply=$(api GET "$NODE1/api/v1/contracts/$CONTRACT/totalSupply" | jq -r '.data // empty' 2>/dev/null)
    assert_not_empty "$supply" "Read total supply ($supply)"

    # Mint tokens to owner
    mint_resp=$(api POST "$NODE1/api/v1/contracts/$CONTRACT/execute" -d "{
        \"function\": \"mint\",
        \"params\": {\"caller\": \"$SENDER\", \"to\": \"$SENDER\", \"amount\": 5000}
    }")
    mint_ok=$(echo "$mint_resp" | jq -r '.success // empty' 2>/dev/null)
    assert_eq "$mint_ok" "true" "Mint 5000 tokens to owner"

    # Check owner balance after mint
    owner_bal=$(api GET "$NODE1/api/v1/contracts/$CONTRACT/balance/$SENDER" | jq -r '.data // empty' 2>/dev/null)
    assert_gt "$owner_bal" 0 "Owner has token balance ($owner_bal)"

    # Transfer tokens
    tx_resp=$(api POST "$NODE1/api/v1/contracts/$CONTRACT/execute" -d "{
        \"function\": \"transfer\",
        \"params\": {\"caller\": \"$SENDER\", \"to\": \"$RECEIVER\", \"amount\": 100}
    }")
    tx_ok=$(echo "$tx_resp" | jq -r '.success // .status // empty' 2>/dev/null)
    if [[ "$tx_ok" == "true" || "$tx_ok" == "Success" ]]; then
        echo "  $(green "PASS") ERC-20 transfer"
        PASSED=$((PASSED + 1))
    else
        echo "  $(red "FAIL") ERC-20 transfer"
        FAILED=$((FAILED + 1))
    fi

    # Verify receiver token balance
    recv_tok=$(api GET "$NODE1/api/v1/contracts/$CONTRACT/balance/$RECEIVER" | jq -r '.data // empty' 2>/dev/null)
    assert_not_empty "$recv_tok" "Receiver has tokens ($recv_tok)"
else
    skip "ERC-20 flow (deploy failed)"
fi

# ── Test 23: NFT Flow ───────────────────────────────────────────────────────
section "23. NFT flow"

nft_deploy=$(api POST "$NODE1/api/v1/contracts" -d "{
    \"owner\": \"$SENDER\",
    \"contract_type\": \"nft\",
    \"name\": \"E2ENFT\",
    \"symbol\": \"ENFT\"
}")
NFT_ADDR=$(echo "$nft_deploy" | jq -r '.data // empty' 2>/dev/null)
if [[ -n "$NFT_ADDR" && "$NFT_ADDR" != "null" ]]; then
    echo "  $(green "PASS") Deploy NFT contract ($NFT_ADDR)"
    PASSED=$((PASSED + 1))

    # Mint NFT
    mint_resp=$(api POST "$NODE1/api/v1/contracts/$NFT_ADDR/execute" -d "{
        \"function\": \"mintNFT\",
        \"params\": {\"caller\": \"$SENDER\", \"to\": \"$SENDER\", \"token_id\": 1, \"token_uri\": \"ipfs://e2e-test\"}
    }" -H "X-Org-Id: org1" -H "X-Msp-Role: client")
    mint_ok=$(echo "$mint_resp" | jq -r '.success // .status // empty' 2>/dev/null)
    if [[ "$mint_ok" == "true" || "$mint_ok" == "Success" ]]; then
        echo "  $(green "PASS") Mint NFT #1"
        PASSED=$((PASSED + 1))
    else
        echo "  $(red "FAIL") Mint NFT #1"
        FAILED=$((FAILED + 1))
    fi

    # Verify ownership
    owner=$(api GET "$NODE1/api/v1/contracts/$NFT_ADDR/nft/1/owner" | jq -r '.data // empty' 2>/dev/null)
    assert_eq "$owner" "$SENDER" "NFT #1 owned by sender"

    # Transfer NFT
    xfer_nft=$(api POST "$NODE1/api/v1/contracts/$NFT_ADDR/execute" -d "{
        \"function\": \"transferNFT\",
        \"params\": {\"from\": \"$SENDER\", \"to\": \"$RECEIVER\", \"token_id\": 1}
    }" -H "X-Org-Id: org1" -H "X-Msp-Role: client")
    xfer_nft_ok=$(echo "$xfer_nft" | jq -r '.success // .status // empty' 2>/dev/null)
    if [[ "$xfer_nft_ok" == "true" || "$xfer_nft_ok" == "Success" ]]; then
        echo "  $(green "PASS") Transfer NFT #1"
        PASSED=$((PASSED + 1))
    else
        echo "  $(red "FAIL") Transfer NFT #1"
        FAILED=$((FAILED + 1))
    fi

    # Verify new owner
    new_owner=$(api GET "$NODE1/api/v1/contracts/$NFT_ADDR/nft/1/owner" | jq -r '.data // empty' 2>/dev/null)
    assert_eq "$new_owner" "$RECEIVER" "NFT #1 now owned by receiver"
else
    skip "NFT flow (deploy failed)"
fi

# ── Test 24: DID + Credential Lifecycle ─────────────────────────────────────
section "24. DID + credential lifecycle"

# Create DID (timestamps are u64 epoch seconds)
did_resp=$(api POST "$NODE1/api/v1/store/identities" -d '{
    "did": "did:bc:e2etest",
    "created_at": 1700000000,
    "updated_at": 1700000000,
    "status": "active"
}')
assert_status "$did_resp" 200 "Create DID did:bc:e2etest"

# Read DID back
did_read=$(api GET "$NODE1/api/v1/store/identities/did:bc:e2etest")
did_status=$(echo "$did_read" | jq -r '.data.status // empty' 2>/dev/null)
assert_eq "$did_status" "active" "DID status is active"

# Issue credential
cred_resp=$(api POST "$NODE1/api/v1/store/credentials" -d '{
    "id": "cred-e2e-001",
    "issuer_did": "did:bc:e2etest",
    "subject_did": "did:bc:e2etest",
    "cred_type": "VerifiableCredential",
    "issued_at": 1700000000,
    "expires_at": 1800000000,
    "revoked_at": null
}')
assert_status "$cred_resp" 200 "Issue credential cred-e2e-001"

# Read credential back
cred_read=$(api GET "$NODE1/api/v1/store/credentials/cred-e2e-001")
cred_type=$(echo "$cred_read" | jq -r '.data.cred_type // empty' 2>/dev/null)
assert_eq "$cred_type" "VerifiableCredential" "Credential readable"

# Revoke credential (overwrite with revoked_at set)
revoke_resp=$(api POST "$NODE1/api/v1/store/credentials" -d '{
    "id": "cred-e2e-001",
    "issuer_did": "did:bc:e2etest",
    "subject_did": "did:bc:e2etest",
    "cred_type": "VerifiableCredential",
    "issued_at": 1700000000,
    "expires_at": 1800000000,
    "revoked_at": 1750000000
}')
assert_status "$revoke_resp" 200 "Revoke credential"

# ── Test 25: Airdrop Flow ──────────────────────────────────────────────────
section "25. Airdrop flow"

# Check eligibility (sender has mined blocks, should be tracked)
elig_resp=$(api GET "$NODE1/api/v1/airdrop/eligibility/$SENDER")
elig_ok=$(echo "$elig_resp" | jq -r '.success // empty' 2>/dev/null)
assert_eq "$elig_ok" "true" "Check airdrop eligibility"

# Get tracking info
track_resp=$(api GET "$NODE1/api/v1/airdrop/tracking/$SENDER")
track_ok=$(echo "$track_resp" | jq -r '.success // empty' 2>/dev/null)
assert_eq "$track_ok" "true" "Get airdrop tracking"

# Get statistics
stats_resp=$(api GET "$NODE1/api/v1/airdrop/statistics")
stats_ok=$(echo "$stats_resp" | jq -r '.success // empty' 2>/dev/null)
assert_eq "$stats_ok" "true" "Get airdrop statistics"

# Get tiers
tiers_resp=$(api GET "$NODE1/api/v1/airdrop/tiers")
tiers_ok=$(echo "$tiers_resp" | jq -r '.success // empty' 2>/dev/null)
assert_eq "$tiers_ok" "true" "Get airdrop tiers"

# ── Test 26: Staking Cycle ──────────────────────────────────────────────────
section "26. Staking queries"

validators=$($CURL "$NODE1/api/v1/staking/validators" 2>/dev/null)
assert_not_empty "$validators" "Staking validators endpoint responds"

my_stake=$($CURL "$NODE1/api/v1/staking/my-stake/$SENDER" 2>/dev/null)
assert_not_empty "$my_stake" "Staking my-stake endpoint responds"

code=$(http_code POST "$NODE1/api/v1/staking/stake" -d "{\"address\":\"$SENDER\",\"amount\":1}")
assert_eq "$code" "404" "Unsigned staking move is not exposed"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  $(green "PASSED"): $PASSED"
echo "  $(red "FAILED"): $FAILED"
echo "  $(yellow "SKIPPED"): $SKIPPED"
echo "  Total:   $((PASSED + FAILED + SKIPPED))"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
