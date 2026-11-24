# Security Audit Package

Prepared for an external security audit. Last updated: 2026-11-24.

## System

Goya is a post-quantum verification ledger written in Rust. Mainnet runs four ML-DSA-65 validators under HotStuff BFT (quorum 3 of 4). Platforms register DIDs, notarize documents and issue credentials through an HTTP API; any verifier checks them without trusting the node.

## Scope, by priority

| Area | Files | Question for the auditor |
|---|---|---|
| BFT consensus | `src/consensus/bft/`, `src/consensus/controller.rs` | Can a Byzantine validator, or a network adversary, fork the chain, stall a correct quorum, or get a vote counted twice? |
| P2P | `src/network/mod.rs`, `src/network_security.rs` | Can an outsider join, impersonate a validator, exhaust memory or connections, or get an honest validator banned? |
| Block validation and state sync | `src/ordering/mod.rs`, `src/mining.rs` | Can a peer make a node persist a block that a quorum did not sign, or diverge its state? |
| Crypto module | `crates/pqc_crypto_module/` | Correct use of AWS-LC ML-DSA-65 and ML-KEM-768, key handling and zeroization, and the module boundary enforced by `tests/crypto_boundary.rs` |
| Write authorization | `src/api/handlers/` (identities, notarize, credentials) | Can a write be accepted without the key holder's signature, or replayed? |

Out of scope: the Tauri desktop app, EVM, bridge and governance modules, which mainnet does not expose.

## Evidence already produced

| Artifact | Where |
|---|---|
| Lean 4 proofs, including HotStuff no-fork (58 theorems and lemmas; they cover models, not the Rust code) | `formal/` |
| Seven-validator testnet across three continents: faults, partitions, a Byzantine validator, load | [TESTNET-2026-11.md](../benchmarks/TESTNET-2026-11.md) |
| Quantum threat lab | [QUANTUM-LAB.md](QUANTUM-LAB.md) |
| NIST ACVP, KAT and Wycheproof vectors, plus cross-checks against two independent ML-DSA implementations | `crates/pqc_crypto_module/tests/` |
| Mainnet operations | [MAINNET-VALIDATORS.md](../../api/MAINNET-VALIDATORS.md) |

Gate run before every release, on cloud builders:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --test crypto_boundary
cargo test --lib
cargo test --doc
cargo test --test bft_e2e --test bft_mldsa65_e2e
cargo test -p pqc_crypto_module --features acvp
```

## Known limitations

- All four validators are operated by Goya.
- The validator set is static configuration; changing it needs a coordinated restart.
- Validator keys are files on disk, not in an HSM or KMS.
- P2P traffic is authenticated by signed handshakes but not encrypted.
- ML-DSA runs on AWS-LC, but no FIPS 140-3 certificate covers its ML-DSA yet.

## Candidate auditors

Rust and consensus specialists to request quotes from: Informal Systems, Trail of Bits, NCC Group, Zellic, Least Authority.
