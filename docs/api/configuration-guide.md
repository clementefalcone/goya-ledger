# Configuration

All configuration is via environment variables. No config files needed.

## Core

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8080` | HTTP API listen port |
| `P2P_PORT` | `8081` | P2P gossip listen port |
| `BIND_ADDR` | `127.0.0.1` | HTTP bind address (`0.0.0.0` in Docker) |
| `NETWORK_ID` | `mainnet` | Network identifier (peers reject mismatched IDs). Also selects the genesis: `mainnet` builds the production genesis (hash `0e1eec13…`, pinned by a test); any other network starts at timestamp 0 and forms a separate chain |
| `DIFFICULTY` | `1` | Mining difficulty |
| `NODE_ROLE` | `peerandorderer` | Node role: `peer`, `orderer`, `peerandorderer` |
| `ORG_ID` | `default` | This node's organization ID |
| `HTTP_KEEP_ALIVE_SECS` | `75` | HTTP keep-alive timeout (seconds) |
| `HTTP_REQUEST_TIMEOUT_SECS` | `30` | Max time to receive a complete request (seconds) |
| `MEMPOOL_MAX_SIZE` | `1000` | Max pending transactions in mempool |
| `LOG_FORMAT` | *(text)* | Log output format: `json` for structured JSON, empty for human-readable text |
| `RUST_LOG` | `info` | Log level filter (e.g. `debug`, `warn`, `rust_bc=debug,actix_web=info`) |

## Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_BACKEND` | *(memory)* | Block store: `rocksdb` or empty for in-memory |
| `STORAGE_PATH` | `./data/rocksdb` | RocksDB data directory |
| `STATE_DB` | *(memory)* | World state: `couchdb` or empty for in-memory |
| `COUCHDB_URL` | `http://localhost:5984` | CouchDB connection URL |
| `COUCHDB_DB` | `world_state` | CouchDB database name |

## Ordering

| Variable | Default | Description |
|----------|---------|-------------|
| `ORDERING_BACKEND` | `solo` | Ordering backend: `solo` or `raft` |
| `RAFT_NODE_ID` | `1` | This node's Raft ID (required when `raft`) |
| `RAFT_PEERS` | `1:127.0.0.1:8087` | Comma-separated `id:host:port` peer map |

## TLS

| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_CERT_PATH` | — | Node TLS certificate (enables HTTPS + P2P TLS) |
| `TLS_KEY_PATH` | — | Node TLS private key |
| `TLS_CA_CERT_PATH` | — | CA certificate for peer verification |
| `MTLS_CERT_PATH` | — | Client certificate for mTLS |
| `MTLS_KEY_PATH` | — | Client key for mTLS |
| `MTLS_CA_PATH` | — | CA for mTLS client verification |

## P2P

| Variable | Default | Description |
|----------|---------|-------------|
| `P2P_EXTERNAL_ADDRESS` | — | Announce address (e.g. `node1:8081`) |
| `BOOTSTRAP_NODES` | — | Comma-separated `host:port` for initial peers |
| `SEED_NODES` | — | Always-tried peer list |
| `PEER_ALLOWLIST` | — | Comma-separated allowed peer addresses |
| `ANCHOR_PEERS` | — | Cross-org gossip anchors |

## Staking

| Variable | Default | Description |
|----------|---------|-------------|
| `MIN_STAKE` | `1000` | Minimum stake amount |
| `UNSTAKING_PERIOD` | `604800` | Unstaking cooldown (seconds, default 7 days) |
| `SLASH_PERCENTAGE` | `5` | Slash percentage for misbehavior |

## Security & CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_BC_ENV` | — | Set to `production` to enforce TLS |
| `ACL_MODE` | `permissive` | `strict` (deny without mTLS identity) or `permissive` (log-only) |
| `CORS_ALLOWED_ORIGINS` | `*` | Comma-separated allowed origins (e.g. `https://app.example.com,https://admin.example.com`) |

### Production Security Requirements

When `RUST_BC_ENV=production`:

1. **TLS is mandatory** — the server will refuse to start without `TLS_CERT_PATH` and `TLS_KEY_PATH`.
2. **ACL_MODE=strict recommended** — permissive mode logs a warning in production because `X-Org-Id` and `X-Msp-Role` headers are spoofable without mTLS.
3. **CORS wildcard discouraged** — set `CORS_ALLOWED_ORIGINS` to specific domains. Wildcard `*` logs a warning in production.

mTLS (`TLS_MUTUAL=true` + `TLS_CA_CERT_PATH`) is the only supported authentication mechanism for production.

## Example: Production multi-node

```bash
# Node 1 (peer + orderer, org1)
API_PORT=8080
P2P_PORT=8081
BIND_ADDR=0.0.0.0
NETWORK_ID=mainnet
ORG_ID=org1
NODE_ROLE=peerandorderer
STORAGE_BACKEND=rocksdb
STORAGE_PATH=/data/blocks
STATE_DB=couchdb
COUCHDB_URL=http://couchdb:5984
ORDERING_BACKEND=raft
RAFT_NODE_ID=1
RAFT_PEERS=1:node1:8081,2:node2:8083,3:node3:8085
TLS_CERT_PATH=/tls/node1.crt
TLS_KEY_PATH=/tls/node1.key
TLS_CA_CERT_PATH=/tls/ca.crt
P2P_EXTERNAL_ADDRESS=node1:8081
BOOTSTRAP_NODES=node2:8083,node3:8085
```
