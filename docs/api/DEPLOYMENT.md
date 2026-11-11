# Deployment Guide

Production deployment of a rust-bc blockchain network.

## Architecture

A minimal production network consists of:

| Component | Count | Role |
|-----------|-------|------|
| Peer nodes | 2+ | Execute chaincode, endorse transactions, store ledger |
| Orderer | 1+ | Order transactions into blocks (Solo or Raft) |
| Prometheus | 1 | Metrics collection |
| Grafana | 1 | Dashboards |

## Docker Compose deployment

### 1. Generate TLS certificates

```bash
cd deploy && bash generate-tls.sh
```

For production, replace with certificates from a trusted CA or your organization's PKI.

### 2. Configure environment

Key environment variables per node:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | 8080 | HTTP API port |
| `P2P_PORT` | 8081 | P2P gossip port |
| `BIND_ADDR` | `127.0.0.1` | Listen address (`0.0.0.0` for containers) |
| `STORAGE_BACKEND` | *(memory)* | Set to `rocksdb` for persistent storage |
| `STORAGE_PATH` | `./data/blocks` | RocksDB data directory |
| `DIFFICULTY` | 1 | Mining difficulty |
| `NETWORK_ID` | `mainnet` | Network identifier |
| `ACL_MODE` | *(strict)* | `permissive` disables ACL enforcement |
| `JWT_SECRET` | `change-me-in-production` | JWT signing secret |

### TLS configuration

| Variable | Description |
|----------|-------------|
| `TLS_CERT_PATH` | Node TLS certificate (enables HTTPS + P2P TLS) |
| `TLS_KEY_PATH` | Node TLS private key |
| `TLS_CA_CERT_PATH` | CA certificate for peer verification |
| `TLS_PINNED_CERTS` | Comma-separated SHA-256 fingerprints (optional) |

### P2P configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `P2P_EXTERNAL_ADDRESS` | — | Announce address (e.g. `node1:8081`) |
| `BOOTSTRAP_NODES` | — | Comma-separated `host:port` list |
| `SEED_NODES` | — | Always-tried peer list |
| `P2P_RESPONSE_BUFFER_BYTES` | 262144 | Response buffer (256 KB) |
| `P2P_HANDLER_BUFFER_BYTES` | 65536 | Handler buffer (64 KB) |

### Ordering configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ORDERING_BACKEND` | `solo` | `solo` or `raft` |
| `RAFT_NODE_ID` | 1 | This node's Raft ID |
| `RAFT_PEERS` | — | `id:host:port` entries (e.g. `1:orderer1:8087,2:orderer2:8087`) |

### 3. Start the network

```bash
docker compose up -d
```

### 4. Verify

```bash
./scripts/bcctl.sh status       # Health of all nodes
./scripts/bcctl.sh consistency  # Compare chain tips across peers
```

## Production checklist

### Security

- [ ] Replace self-signed TLS certificates with CA-issued ones
- [ ] Set `JWT_SECRET` to a strong random value
- [ ] Set `ACL_MODE` to strict (default) — never run permissive in production
- [ ] Review `PEER_ALLOWLIST` to restrict inbound P2P connections
- [ ] Enable `TLS_PINNED_CERTS` for certificate pinning
- [ ] Rotate TLS certificates via SIGHUP or `TLS_RELOAD_INTERVAL`

### Storage

- [ ] Set `STORAGE_BACKEND=rocksdb` on all nodes
- [ ] Mount `/app/data` as a named Docker volume or persistent disk
- [ ] If RocksDB fails to open, the node now exits (no silent fallback)

### Monitoring

- [ ] Prometheus scraping `/metrics` on each node
- [ ] Grafana dashboards for block height, peer count, transaction throughput
- [ ] Alert on `/api/v1/health` returning `"degraded"` status

### Networking

- [ ] Use `P2P_EXTERNAL_ADDRESS` when nodes are behind NAT/load balancer
- [ ] Set `BOOTSTRAP_NODES` on every peer for initial discovery

### Backup

- [ ] Snapshot RocksDB data directory (`/app/data`) periodically
- [ ] Use `POST /api/v1/snapshots/{channel_id}` for application-level snapshots
- [ ] Test restore from snapshot before relying on it

## Ports reference

| Service | Default port | Protocol |
|---------|-------------|----------|
| API (HTTPS) | 8080 | HTTPS (TLS) |
| P2P | 8081 | TCP (TLS) |
| Prometheus | 9090 | HTTP |
| Grafana | 3000 | HTTP |

## Graceful shutdown

The node handles SIGTERM and Ctrl-C:

1. Stops accepting new HTTP connections
2. Drains in-flight requests (10s timeout)
3. Aborts background tasks (gossip, discovery, sync, purge)
4. Flushes RocksDB WAL
5. Exits with code 0

```bash
docker compose stop   # sends SIGTERM, waits 10s, then SIGKILL
```
