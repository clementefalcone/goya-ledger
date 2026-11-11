# CIR 2025/2531 — Qualified Electronic Ledger Mapping

eIDAS 2.0 Art. 45i compliance mapping for Goya Ledger.

Audit date: 2026-08-31 · Codebase: v0.13.3

> Self-assessment. No CAB has validated these claims.

---

## Art. 45i requirements

### 1. Sequential ordering of data records

| Requirement | Goya control | Evidence |
|---|---|---|
| Monotonic block height | `Block::height: u64`, genesis = 0, each block = `latest + 1` | `src/storage/traits.rs:19`, `src/mining.rs:71-76` |
| Parent hash chain | `Block::parent_hash: [u8; 32]` — SHA-256 of predecessor | `src/storage/traits.rs:21` |
| FIFO transaction ordering | `OrderingService` batches endorsed txs from `VecDeque` | `src/ordering/service.rs:11-13` |
| BFT round serialization | `VoteMessage::round: u64` — monotonically increasing | `src/consensus/bft/types.rs:39` |
| Light client header chain | `HeaderChain::append()` validates height monotonicity + parent linkage | `src/light_client/header.rs:86-100` |

### 2. Time stamping

| Requirement | Goya control | Evidence |
|---|---|---|
| Block timestamp | `Block::timestamp: u64` (UNIX UTC) on every block | `src/storage/traits.rs:20` |
| Transaction timestamp | `Transaction::timestamp: u64` on every transaction | `src/storage/traits.rs:98` |
| RFC 3161 TSA | `TsaProvider` with monotonic serial, policy OID, accuracy metadata | `src/tsa/mod.rs:98-107` |
| DER-encoded timestamps | `POST /api/v1/tsa/timestamp/der` → `application/timestamp-reply` | `src/api/handlers/tsa.rs:74-101` |
| Timestamp verification | `POST /api/v1/tsa/verify` validates token signatures | `src/api/handlers/tsa.rs:104-122` |
| Trusted time source | `trait TimeSource` with System/NTP/Simulated, drift guard (5s default) | `src/time_source.rs:50-70` |

### 3. Tamper evidence

| Requirement | Goya control | Evidence |
|---|---|---|
| Hash chain | `Block::parent_hash` — SHA-256 back-link per block | `src/storage/traits.rs:21` |
| Merkle root | `Block::merkle_root: [u8; 32]` over transaction IDs | `src/storage/traits.rs:22`, `src/mining.rs:109-110` |
| Chain verification API | `GET /api/v1/chain/verify` — walks all blocks, reports first invalid height | `src/api/handlers/chain.rs:27-78` |
| Canonical block hash | `compute_block_hash()` = SHA-256(height ‖ parent_hash ‖ merkle_root ‖ timestamp ‖ proposer) | `src/api/handlers/chain.rs:11-18` |
| Audit log hash chain | `AuditEntry::previous_hash` + `entry_hash` — SHA-256 linked | `src/audit.rs:134-139` |
| Audit chain verification | `verify_audit_chain()` — walks log, returns first broken link | `src/audit.rs:180-190` |
| FIPS 140-3 KAT | `run_hash_self_tests()` — SHA-256 + SHA3-256 CAVP vectors at startup | `src/crypto/hasher.rs:59-93` |

### 4. Data origin authentication

| Requirement | Goya control | Evidence |
|---|---|---|
| Block proposer signature | `Block::signature` + `signature_algorithm` (Ed25519 / ML-DSA-65) | `src/storage/traits.rs:26-29` |
| Dual (hybrid) signatures | `Block::secondary_signature` — classical + PQC on same block | `src/storage/traits.rs:38-42` |
| Orderer signature | `sign_block_with_provider()` over `SHA-256(height ‖ parent_hash ‖ merkle_root)` | `src/ordering/mod.rs:29-57` |
| BFT vote signatures | `VoteMessage::signature` with domain `GOYA-BFT-VOTE-V1` | `src/consensus/bft/types.rs:44-51` |
| Quorum certificate | `QuorumCertificate` aggregates validated votes ≥ 2f+1 | `src/consensus/bft/types.rs:106-116` |
| Multi-org endorsements | `Block::endorsements: Vec<Endorsement>` | `src/storage/traits.rs:32` |
| eIDAS signature levels | `SignatureLevel::{Simple, Advanced, Qualified}` per Art. 3(10-12) | `src/signature/mod.rs:41-59` |
| Signing algorithm support | Ed25519, ML-DSA-65, SLH-DSA-128s, RSA, ECDSA-P256 | `src/identity/signing.rs:26-35` |
| Validator key registry | `ValidatorRegistry` maps validator ID → ML-DSA-65 pubkey | `src/consensus/bft/validator_registry.rs:16-17` |

### 5. Unique identifiers

| Requirement | Goya control | Evidence |
|---|---|---|
| Transaction ID | `Transaction::id` — UUID v4 | `src/storage/traits.rs:95`, `src/block_creation.rs:21` |
| Block height | `Block::height: u64` — unique monotonic index | `src/storage/traits.rs:19` |
| Block hash | Deterministic SHA-256 from canonical fields | `src/api/handlers/chain.rs:11-18` |
| DID | `did:goya:{pubkey_hex[..16]}` — globally unique | `src/identity/did.rs` |
| TSA serial number | `AtomicU64` monotonic per `TsaProvider` instance | `src/tsa/mod.rs:100-101` |
| Audit trace ID | UUID v4 per `AuditEntry` | `src/audit.rs:129` |
| Replay prevention | `BlockStore::mark_tx_seen()` / `is_tx_seen()` — dedup across restarts | `src/storage/traits.rs:576-583` |

### 6. Immutability (append-only)

| Requirement | Goya control | Evidence |
|---|---|---|
| No block deletion | `trait BlockStore` exposes `write_block` / `read_block` — no `delete_block` | `src/storage/traits.rs:516-1029` |
| No audit deletion | `trait AuditStore` exposes `append()` — no `delete()` | `src/audit.rs:231-243` |
| Hash chain detection | Deletion/modification breaks `parent_hash` or `previous_hash` chain | Tests: `mine_second_block_links_parent` |
| 7-year retention | `DEFAULT_RETENTION_SECS` = 7 years (ETSI TS 102 042) | `src/audit_retention.rs:11-15` |
| 15-year UAE retention | `UAE_RETENTION_SECS` configurable per jurisdiction | `src/audit_retention.rs` |

### 7. Consensus mechanism

| Requirement | Goya control | Evidence |
|---|---|---|
| BFT protocol | HotStuff-inspired 4-phase: Prepare → PreCommit → Commit → Decide | `src/consensus/bft/types.rs:5-19` |
| Fault tolerance | f = (n−1)/3, quorum = 2f+1, minimum n=4 | `src/consensus/bft/quorum.rs:50-79` |
| Safety (no fork) | `SafetyState` with `high_qc` / `locked_qc` locking (two-chain/three-chain) | `src/consensus/bft/safety.rs:1-14` |
| Formal safety proof | Lean 4: `no_fork` — with 3f+1 validators and at most f faulty, two blocks with a CommitQC never conflict, under the voting rules of `safe_to_vote` (assumptions mapped to code in `formal/README.md`) | `formal/Formal/HotStuffSafety.lean` |
| Leader rotation | Round-robin with exponential backoff timeouts | `src/consensus/bft/round_manager.rs:48-66` |
| Equivocation detection | Dedicated module for conflicting-vote detection | `src/consensus/equivocation.rs` |
| Slashing | Penalty mechanism for Byzantine validators | `src/consensus/slashing.rs` |
| Ancestry verification | `ChainAncestryChecker` backed by block store, fail-closed | `src/consensus/bft/safety.rs:46-97` |

### 8. Auditability

| Requirement | Goya control | Evidence |
|---|---|---|
| Semantic audit actions | 40+ `AuditAction` variants (ETSI TS 102 042 aligned) | `src/audit.rs:19-107` |
| Hash-chained audit log | `AuditEntry::previous_hash` + `entry_hash` | `src/audit.rs:134-139` |
| Audit query API | `GET /api/v1/audit/requests` — paginated, filterable | `src/api/handlers/audit.rs:27-68` |
| CSV export | `GET /api/v1/audit/export` | `src/api/handlers/audit.rs:71-91` |
| Chain verification API | `GET /api/v1/chain/verify` + `GET /api/v1/chain/info` | `src/api/handlers/chain.rs` |
| Audit integrity check | `verify_audit_chain()` — cryptographic hash chain walk | `src/audit.rs:180-190` |
| Retention enforcement | Auto-purge disabled by default, configurable per jurisdiction | `src/audit_retention.rs` |

---

## Summary

| Dimension | Status | Gaps |
|---|---|---|
| Sequential ordering | Covered | None |
| Time stamping | Covered | TSA not yet qualified (requires QTSP) |
| Tamper evidence | Covered | None |
| Data origin authentication | Covered | Qualified signatures require QSCD (Gap 10) |
| Unique identifiers | Covered | None |
| Immutability | Covered | None |
| Consensus | Covered | Formal proof exists (Lean 4) |
| Auditability | Covered | CAB validation pending |

All 8 Art. 45i technical dimensions are implemented. Remaining blockers are organizational:

1. **Qualified status** requires QTSP certification (Gap 11) — the ledger itself is technically ready
2. **Qualified timestamps** require the TSA to operate under a QTSP
3. **Qualified signatures** require QSCD integration (Gap 10)
4. **CAB validation** of audit and security controls (Gap 6)
