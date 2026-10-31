# GOYA Ledger

[![CI](https://github.com/clementeaf/goya-ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/clementeaf/goya-ledger/actions/workflows/ci.yml)

Blockchain platform with post-quantum cryptography. Identity, notarization, wallet, and governance — all from a desktop app.

## What can you do?

### Identity
Create a `did:goya:` decentralized identity with Ed25519 signing. Private key encrypted locally (Argon2id + AES-256-GCM) — never leaves your machine.

### Notarize
Drag and drop any file. SHA-256 hash computed locally, signed with your identity, registered on-chain. The document is never uploaded.

### Verify
Paste a hash to check if it was notarized — timestamp, signer, block height.

### Wallet
View your balance, request testnet tokens (faucet), send signed transfers to other identities, and browse transaction history.

### Governance
Browse active proposals, create new ones, cast signed votes, and view the tally. Every vote is cryptographically bound to your identity.

## How it works

```
Your Mac                           GOYA Network
┌──────────────┐                  ┌──────────────┐
│ Desktop App  │───HTTPS/TLS────▶│  Seed Node   │
│              │                  │  (VPS)       │
│ • Identity   │                  │              │
│ • Notarize   │                  │ • Consensus  │
│ • Verify     │                  │ • Storage    │
│ • Wallet     │                  │ • API        │
│ • Governance │                  │              │
│              │                  │ RocksDB      │
│ Keys stored  │                  │ persistent   │
│ locally in   │                  │              │
│ ~/.goya/     │                  │              │
└──────────────┘                  └──────────────┘
```

## For developers

### Run a local node

```bash
cargo run --bin rust-bc    # API on :8080, P2P on :8081
```

### Build the desktop app

```bash
cd tauri-app && cargo tauri build
```

### Run tests

```bash
cargo test --lib                          # 3007 unit tests
cargo test -p goya-ledger-app             # 35 desktop app tests
cargo test --test service_e2e             # 12 E2E tests against live seed node
```

### API

300+ REST endpoints under `/api/v1`:

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/notarize` | Register a signed document hash |
| `GET /api/v1/notarize/verify/{hash}` | Verify a document hash |
| `GET /api/v1/accounts/{address}` | Balance and nonce |
| `POST /api/v1/transactions` | Submit a signed transfer |
| `GET /api/v1/wallets/{address}/transactions` | Transaction history |
| `POST /api/v1/governance/proposals` | Create a proposal |
| `POST /api/v1/governance/proposals/{id}/vote` | Cast a signed vote |
| `GET /api/v1/governance/proposals/{id}/tally` | View vote results |
| `GET /api/v1/health` | Node health and chain height |

### Architecture

Rust/Actix-Web 4 blockchain node with DAG + HotStuff BFT + DPoS consensus. Post-quantum crypto via ML-DSA-65 (FIPS 204). See [`docs/`](docs/) for full architecture and API reference.

## License

[MIT](LICENSE)
