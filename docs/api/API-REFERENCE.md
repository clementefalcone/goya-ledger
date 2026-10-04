# API Reference

Base URL: `https://localhost:8080/api/v1`

All responses use the gateway envelope: `{ status, status_code, message, data, error, timestamp, trace_id }`. Legacy endpoints use `{ success, data, message }`.

Headers: `Content-Type: application/json`. Channel-scoped endpoints accept `X-Channel-Id` (default: `"default"`). Org-scoped endpoints require `X-Org-Id`.

---

## Health & Utilities

### GET /health

```bash
curl -sk https://localhost:8080/api/v1/health | jq .data
```

```json
{
  "status": "healthy",
  "uptime_seconds": 120,
  "blockchain": { "height": 5, "last_block_hash": "abc...", "validators_count": 0 },
  "checks": { "storage": "ok", "peers": "ok (3 connected)", "ordering": "ok" }
}
```

### GET /version

```json
{ "api_version": "1.0.0", "rust_bc_version": "0.1.0", "blockchain_height": 5 }
```

### GET /openapi.json

Returns OpenAPI 3.0 spec.

### GET /metrics

Prometheus text format (outside `/api/v1` scope).

---

## Gateway (Endorse -> Order -> Commit)

### POST /gateway/submit

Submit a transaction through the full pipeline.

```bash
curl -sk https://localhost:8080/api/v1/gateway/submit -X POST \
  -H 'Content-Type: application/json' \
  -d '{
    "chaincode_id": "mycc",
    "channel_id": "mychannel",
    "transaction": {
      "id": "tx-001",
      "input_did": "did:bc:alice",
      "output_recipient": "did:bc:bob",
      "amount": 100
    }
  }'
```

```json
{ "tx_id": "tx-001", "block_height": 3, "valid": true }
```

---

## Blocks

### GET /blocks

Returns full blockchain as array.

### GET /blocks/index/{index}

Get block by height.

### GET /blocks/{hash}

Get block by hash.

### POST /blocks

Mine a block with transactions. Body: `{ data, miner_address }`.

### GET /store/blocks?page=1&limit=10

Paginated block list from storage layer.

### GET /store/blocks/latest

Returns latest block height.

### GET /store/blocks/{height}

Get block at height from storage layer.

### GET /store/blocks/{height}/transactions

List transactions in a block (secondary index query).

---

## Transactions

### POST /transactions

Create, validate, and enqueue a transaction.

```bash
curl -sk https://localhost:8080/api/v1/transactions -X POST \
  -d '{ "from": "addr1", "to": "addr2", "amount": 50, "fee": 1 }'
```

### GET /mempool

```json
{ "count": 2, "transactions": [...] }
```

### POST /store/transactions

Persist a transaction to the store. Returns 201.

```bash
curl -sk https://localhost:8080/api/v1/store/transactions -X POST \
  -d '{ "id": "tx-1", "block_height": 0, "timestamp": 0, "input_did": "did:bc:alice", "output_recipient": "did:bc:bob", "amount": 42, "state": "pending" }'
```

### GET /store/transactions/{tx_id}

Read a transaction from the store.

---

## Channels

### POST /channels

```bash
curl -sk https://localhost:8080/api/v1/channels -X POST \
  -d '{ "channel_id": "mychannel" }'
```

Returns 201: `{ "channel_id": "mychannel" }`.

### GET /channels

List all channels.

### POST /channels/{channel_id}/config

Update channel configuration (requires endorsement signatures).

### GET /channels/{channel_id}/config

Get latest channel config.

### GET /channels/{channel_id}/config/history

Get config version history.

---

## Organizations

### POST /store/organizations

```bash
curl -sk https://localhost:8080/api/v1/store/organizations -X POST \
  -d '{ "org_id": "org1", "name": "Organization 1", "msp_id": "Org1MSP" }'
```

### GET /store/organizations

List all organizations.

### GET /store/organizations/{org_id}

Get organization by ID.

---

## Endorsement Policies

### POST /store/policies

```bash
curl -sk https://localhost:8080/api/v1/store/policies -X POST \
  -d '{ "resource_id": "mychannel/mycc", "policy": { "NOutOf": { "n": 2, "orgs": ["org1", "org2"] } } }'
```

### GET /store/policies/{resource_id}

Get policy for resource.

---

## Chaincode Lifecycle

### POST /chaincode/install?chaincode_id={id}&version={v}

Upload Wasm binary. Content-Type: `application/octet-stream`.

```bash
curl -sk "https://localhost:8080/api/v1/chaincode/install?chaincode_id=basic&version=1.0" \
  -X POST --data-binary @chaincode.wasm -H 'Content-Type: application/octet-stream'
```

```json
{ "chaincode_id": "basic", "version": "1.0", "size_bytes": 529 }
```

### POST /chaincode/{id}/approve?version={v}

Approve chaincode for your organization. Requires `X-Org-Id` header.

### POST /chaincode/{id}/commit?version={v}

Commit chaincode (requires policy satisfaction).

### POST /chaincode/{id}/simulate?version={v}

Simulate chaincode invocation (read-only).

```json
{ "result": "...", "rwset": { "reads": [...], "writes": [...] } }
```

---

## Private Data Collections

### POST /private-data/collections

```bash
curl -sk https://localhost:8080/api/v1/private-data/collections -X POST \
  -d '{ "name": "secret-data", "member_org_ids": ["org1", "org2"] }'
```

### PUT /private-data/{collection}/{key}

Requires `X-Org-Id` header (must be collection member).

```bash
curl -sk https://localhost:8080/api/v1/private-data/secret-data/mykey -X PUT \
  -H 'X-Org-Id: org1' -d '{ "value": "secret-value" }'
```

```json
{ "collection": "secret-data", "key": "mykey", "hash": "abc123..." }
```

### GET /private-data/{collection}/{key}

Requires `X-Org-Id` header. Returns 403 for non-members.

---

## Discovery Service

### POST /discovery/register

Register a peer in the discovery service.

```bash
curl -sk https://localhost:8080/api/v1/discovery/register -X POST \
  -d '{ "peer_address": "node1:8081", "org_id": "org1", "role": "Peer", "chaincodes": ["mycc"], "channels": ["mychannel"] }'
```

### GET /discovery/endorsers?chaincode={id}&channel={ch}

Get endorsement plan (list of peers that can endorse).

### GET /discovery/peers?channel={id}

List peers on a channel.

---

## ACL (Access Control)

### POST /acls

```bash
curl -sk https://localhost:8080/api/v1/acls -X POST \
  -d '{ "resource": "peer/ChaincodeToChaincode", "policy_ref": "mycc_policy" }'
```

### GET /acls

List all ACL entries.

### GET /acls/{resource}

Get ACL for a specific resource.

---

## MSP (Membership Service Provider)

### POST /msp/{msp_id}/revoke

Add a certificate serial to the CRL.

```bash
curl -sk https://localhost:8080/api/v1/msp/Org1MSP/revoke -X POST \
  -H 'X-MSP-Role: admin' -d '{ "serial": "ABC123" }'
```

### GET /msp/{msp_id}

Get MSP info (CRL size).

---

## Identity & Credentials

### POST /identity/create

Create a DID + Ed25519 keypair. Body: `{ "name": "Alice" }`.

### GET /identity/{did}

Fetch DID document.

### POST /store/identities

Persist identity record. `did` must be derived from `public_key`, and `signature` must be the key holder's signature over `identity:register:{did}`. Wrong signature returns 401.

### GET /store/identities/{did}

Read identity record.

### POST /credentials/issue

Issue a verifiable credential.

### POST /credentials/{id}/verify

Verify credential signature and expiry.

### POST /store/credentials

Persist credential to store.

### GET /store/credentials/{cred_id}

Read credential.

### GET /store/credentials/by-subject/{subject_did}

List credentials by subject DID.

---

## Events (WebSocket)

### GET /events/blocks?from_height=N

Long-poll or WebSocket upgrade. Returns block events from `from_height`.

### GET /events/blocks/filtered

WebSocket stream of filtered block summaries (tx IDs + validation codes, no payloads).

### GET /events/blocks/private

WebSocket stream with private data for authorized orgs. Requires `X-Org-Id` header.

---

## Snapshots

### POST /snapshots/{channel_id}

Create state snapshot.

### GET /snapshots/{channel_id}

List snapshots.

### GET /snapshots/{channel_id}/{snapshot_id}

Download snapshot binary.

---

## Wallets (Legacy)

### POST /wallets/create

Create new wallet. Returns `{ address, balance, public_key }`.

### GET /wallets/{address}

Get wallet balance and info.

---

## Mining (Legacy)

### POST /mine

```bash
curl -sk https://localhost:8080/api/v1/mine -X POST \
  -d '{ "miner_address": "abc123" }'
```

```json
{ "hash": "...", "reward": 50, "transactions_count": 3 }
```

---

## Chain Info (Legacy)

### GET /chain/verify

```json
{ "valid": true, "block_count": 10 }
```

### GET /chain/info

```json
{ "block_count": 10, "difficulty": 1, "latest_block_hash": "...", "is_valid": true }
```
