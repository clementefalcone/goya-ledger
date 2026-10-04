# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org)

---

## [0.19.0] — 2026-10-04

### Security
- Incoming blocks are validated before commit: merkle root over transaction data, parent hash, and a signature from `TRUSTED_BLOCK_SIGNERS` or this node
- Notarizations prove the signer key belongs to the claimed DID and fail when unverified; FEA needs a signer proof from the holder's key
- LexChain binds each party's signer key to its DID
- Identity: registered DID must derive from its key; `POST /store/identities` needs the key holder's signature over `identity:register:{did}` instead of an mTLS ACL; revoke and migrate need the owner's signature, and migration targets an owner-generated key
- Alias register/revoke bind the signer key to the alias DID

### Changed
- Notarizations replicate as a transaction payload; `embedded_entries` removed
- Genesis is deterministic; on `mainnet` it reproduces the production chain's block 0
- Public node endpoints on the VPS are exposed only at `server1.useremotion.com/goya/api/v1/{health,store/identities}` with nginx rate limits (`deploy/vps/goya-node-server1.locations.nginx`); `node.goyaledger.com` was retired
- Cargo builds bounded in memory via `.cargo/config.toml`

### Removed
- Dead `rotate-key` endpoint

## [0.18.0] — 2026-09-24

### Changed — DID Hardening + Identity Federation (P0–P6)

#### P0: DID derivation hardened
- `did_from_pubkey_hex` upgraded from truncated `pubkey_hex[..16]` (64-bit) to SHA3-512 (512-bit, 256-bit quantum security)
- DID format: `did:goya:{128 hex chars}` — birthday bound at 2²⁵⁶
- `civil_anchor_hash(doc_type, doc_number)` — SHA3-512 lookup index for civil document dedup
- `IdentityRecord.civil_anchor` field (optional, backwards-compatible)
- `write_civil_anchor` / `resolve_by_civil_anchor` on MemoryStore + RocksDB (`civil_anchors` column family)
- `GET /identity/resolve/{doc_type}/{doc_number}` — resolve DID from civil document, ACL-protected
- `CreateIdentityRequest` accepts optional `document_type` + `document_number`
- 3 inline DID bypasses (OID4VCI/OID4VP) consolidated to canonical `did_from_pubkey_hex`

#### P1: Typed transaction payload
- `TxPayload` enum: `Transfer { amount }`, `RegisterIdentity { record, civil_anchor }`
- `Transaction.payload: Option<TxPayload>` — `serde(default)`, backwards-compatible with legacy JSON
- All ~100 Transaction/Block struct literals updated

#### P2: Identity as transaction
- `apply_tx_payload(store, tx)` — centralized dispatcher for payload side-effects
- `create_identity` handler builds a Transaction with `RegisterIdentity` payload instead of direct store write
- Civil anchor dedup: duplicate anchor → `409 Conflict`
- Mining commit path wires `apply_tx_payload` for each tx

#### P3: Block carries full transaction data
- `Block.transaction_data: Vec<Transaction>` — blocks are self-contained (like Fabric/Ethereum)
- `OrderingService.cut_block` and `RaftService.cut_block` preserve full tx objects in block
- `MiningService.mine_block` populates `transaction_data`
- `OrderedBlock` handler: peers apply payloads + persist tx from `block.transaction_data`
- BFT `commit_block` applies payloads at commit time
- State sync automatic — `StateResponse` blocks carry tx data

#### P4: Cross-node dedup via civil anchor
- All 4 commit paths (mining, BFT, network, API) mark duplicate-anchor tx as `invalid_payload`
- API returns `409 Conflict` when civil anchor already registered

#### P5: State sync applies identity payloads
- Both `request_state_sync` and `start_pull_sync_loop` replay tx payloads from received blocks
- New node reconstructs full identity store by replaying historical blocks

#### P6: Legacy DID migration
- `migrate_legacy_dids(store)` — idempotent migration of 16-char DIDs to SHA3-512
- Detects legacy by suffix length (!= 128 hex chars)
- Sets `migrated_from` to preserve lineage, migrates civil anchor index
- Skips if new DID already exists, reports errors for empty public keys
- Historical data (transactions, credentials, blocks) left intact

### Deployment
- Auto-migrate legacy DIDs at boot (`main.rs`, RocksDB path)
- `STORAGE_BACKEND=rocksdb` enabled on VPS `162.254.32.12`
- PM2 ecosystem config updated, process saved for reboot recovery
- 3 E2E federation tests: cross-node replication, dedup, state sync replay

### Stats
- `hash_sha3_512` added to crypto hasher (FIPS 202)
- 2849 lib + 6 integration tests pass, clippy clean
- 6 commit paths wired to `apply_tx_payload`: mining, BFT, OrderedBlock, 2x state sync, API

---

## [0.17.6] — 2026-09-15

### Added — OID4VCI Credential Offer by Reference + Partisia Interop

#### Credential offer by-reference with session ID
- `CredentialOfferStore` persists offers in memory (10min TTL)
- `POST /credential_offer` returns `credential_offer_uri=` (by-reference, not inline)
- `GET /credential_offer/{session_id}` serves stored offer — standard OID4VCI wallet fetch
- QR codes encode the by-reference URI for wallet scanning

#### jwt_vc_json-ld credential configuration
- `goya_identity_jwt_vc_json_ld` added to issuer metadata
- W3C VC Data Model v2 with `@context`, `credentialSubject`, ES256/EdDSA
- `issue_sd_jwt_vc_w3c` — SD-JWT with `vc` wrapper (claims in `vc.credentialSubject._sd`)
- Payload matches W3C JWT encoding: `iss`, `sub`, `nbf`, `exp`, `vc`

#### Metadata hardening for wallet compatibility
- `authorization_servers` added to issuer metadata (self-referencing)
- `credential_definition` with `@context` on all credential configurations
- `credential_definition.type` as array on all configs
- `did:jwk` extraction from proof `kid` header for holder binding

#### Deployment
- Caddyfile: `/.well-known/*` routed to node backend (was falling through to explorer SPA)
- nginx: `/.well-known/openid-credential-issuer`, `oauth-authorization-server`, `jwt-vc-issuer` proxied to node
- Dockerfile.prebuilt base upgraded to `debian:trixie-slim` (glibc 2.40 compat)

### Research — Partisia Wallet Interop Analysis
- Partisia ID Wallet is a closed client of `registry.gitlab.com/secata/platform/did/release/issuer-backend`
- Wallet uses strict Kotlin deserialization — unknown JWT fields crash the parser
- Full OID4VCI protocol flow verified end-to-end (metadata → token → credential)
- Credential format requires Partisia's own issuance service Docker container for wallet acceptance
- Goya OID4VCI remains fully compatible with standard wallets (EUDI Reference, Sphereon, Walt.id)

### Stats
- 56 OID4VCI tests pass, clippy clean
- Live at goyaledger.com with all endpoints operational

---

## [0.17.5] — 2026-09-10

### Fixed — EUDI Wallet Critical Security + Route Gaps

#### Proof JWT signature verification (CRITICAL)
- `verify_proof_jwt` now cryptographically verifies the JWT signature against the embedded JWK
- Previously only validated claims (nonce, aud, iat) — an attacker could forge a proof with correct claims but bogus signature
- Supports ES256, EdDSA, RS256 — same pattern as the already-secure `verify_dpop_proof`
- Returns parsed header (with JWK) for downstream key binding

#### OID4VCI route registration (5 endpoints were 404 in production)
- `GET /.well-known/oauth-authorization-server` — OAuth AS metadata (RFC 8414)
- `GET /.well-known/jwt-vc-issuer` — issuer JWKS for SD-JWT VC verification
- `POST /as/par` — Pushed Authorization Request (RFC 9126)
- `GET /authorize` — authorization code flow
- `GET /credential_offer` — credential offer by reference

#### Status claim in SD-JWT VC
- `VcClaims.status` field added (optional, `serde(default)`)
- `issue_sd_jwt_vc` embeds `status` in JWT payload when present
- OID4VCI `issue_sd_jwt_credential` wires `status_ref` → Token Status List URI + index
- Wallet/verifier can now discover revocation endpoint from the credential itself

#### GDPR/Ley 21.719 data separation (on-chain privacy)
- `PrivateClaimsStore` — off-chain store for personal claims (in-memory, deletable)
- Credential issuance: personal claims stored off-chain, on-chain only `claims_commitment = H(claims || salt)`
- `POST /credentials/{id}/erase-claims` — GDPR Art. 17 right of erasure: destroys off-chain claims, commitment remains orphaned on-chain
- `Credential.claims_commitment` and `claims_salt` fields added (serde default, backwards-compatible)
- Read path reconstitutes claims from off-chain store when available
- Legal basis: EDPB blockchain guidelines, GDPR Art. 17, Ley 21.719 (Chile)

### Stats
- 56 OID4VCI tests, 25 SD-JWT tests, 7 EUDI interop tests, 5 privacy tests pass, clippy clean

---

## [0.17.4] — 2026-09-09

### Added — Tokenomics Wiring

Connected the existing tokenomics engine (`EconomicsState`, `DepositLedger`,
`StakingRewardContract`) to the runtime — previously all code existed in
isolation with zero integration.

#### EconomicsState → runtime (7 gaps closed)
1. `EconomicsState` added to `AppState` — shared via `Arc<Mutex<_>>`
2. `MiningService::mine_block()` calls `process_block()` — updates total_minted, base_fee, epoch
3. API mine handler reads reward from `EconomicsState` instead of hardcoded `50u64`
4. `fee: u64` field added to `Transaction` (serde default, backwards-compatible)
5. `mine_block()` sums transaction fees → `process_block(total_fees)` → 80% burn / 20% proposer
6. `DepositLedger` added to `AppState`
7. `committee_from_staking_manager()` bridges `StakingManager` → DPoS `ValidatorCommittee`

#### Tokenomics API endpoints
- `GET /api/v1/tokenomics/supply` — max_supply, total_minted, total_burned, circulating_supply
- `GET /api/v1/tokenomics/fee` — base_fee, min_tx_fee, burn/proposer split
- `GET /api/v1/tokenomics/inflation` — annual rate, epoch, block reward, next halving

### Stats
- ~60 Transaction constructors updated with `fee: 0`
- 2829 tests pass, clippy clean

---

## [0.17.3] — 2026-09-09

### Added — Digital Identity Hardening

#### W3C DID Document compliance (6 fixes)
- `resolve_did` returns real public key from `IdentityRecord`, not truncated DID suffix
- `assertionMethod` added to DID Document (W3C DID Core requirement for VC issuance)
- `authentication` and `assertionMethod` as string references to `verificationMethod` (W3C pattern)
- `@context` dynamic per algorithm: `ed25519-2020/v1`, `multikey/v1`, `jws-2020/v1`
- `signature_algorithm` field added to `IdentityRecord` (backwards-compatible, `serde(default)`)
- `get_credential_as_vc` proof type resolved from issuer's algorithm, not hardcoded Ed25519

#### DID Auth challenge-response
- `POST /identity/auth/challenge`: server issues UUID v4 nonce with 5-minute TTL
- `POST /identity/auth/verify`: client signs nonce, server verifies against registered public key
- Single-use nonces, algorithm-aware (Ed25519, ML-DSA-65)

#### Key recovery (Shamir Secret Sharing)
- `identity/key_recovery.rs`: Shamir SSS over GF(256), zero new dependencies
- `split(secret, threshold, total)` → N shares, any K reconstruct
- SHA-256 checksum detects corrupted shares
- Tested with Ed25519 (32B) and ML-DSA-65 (4032B) key sizes

#### Identity architecture document
- `docs/architecture/IDENTITY.md`: complete identity subsystem reference
- Module map, DID scheme, 5 algorithms, key lifecycle, credential formats
- DID Auth flow, W3C interop, RA multi-jurisdiction, EUDI ARF v3.0

### Removed — Dead code cleanup
- `DidDocument`, `DidStatus`, `DidMetadata` structs (unused, replaced by `interop.rs` W3C version)
- `IdentityConfig` struct and Default impl (never consumed by runtime)
- ~280 lines and 13 tests of dead code eliminated

### Stats
- 14 identity source files, ~7000 lines
- 285 identity unit tests, clippy clean
- 9 new key recovery tests, 2 new DID Auth tests

---

## [0.17.2] — 2026-09-08

### Research — NOTA Token Thesis: Federated PSC Governance

Documented the architectural discovery that Goya's multi-jurisdictional
PSC model (Chile/Estonia/UAE) naturally requires a governance token —
not as speculative cryptocurrency, but as operational settlement and
decentralized governance mechanism for a federated network of Trust
Service Providers.

#### Key findings
- DLT permissioned network eliminates PoW/mining — validators are accredited PSCs
- Each jurisdiction requires a separate legal entity + accreditation → independent PSCs sharing infrastructure
- Token solves inter-jurisdictional settlement (no shared bank/currency between PSCs)
- Decentralized governance is essential: DID sovereignty requires that no single entity controls identity
- Existing code supports this: `src/governance/voting.rs`, `src/governance/params.rs`, `src/staking/`, DPoS consensus
- Tokenomics module (`src/tokenomics/`) has supply cap (100M), halving, fee burn — but is not yet wired to block production

#### NOTA token thesis
> NOTA is the governance mechanism of a federated network of post-quantum
> Trust Service Providers, where digital identity depends on multi-jurisdictional
> consensus of accredited PSCs, not on any single government or corporation.

#### Gap identified
- `EconomicsEngine` and `SupplyState` exist but are not connected to the block production runtime
- Activation requires ~50 lines wiring rewards to validators and fee burns to transactions

---

## [0.17.1] — 2026-09-08

### Added — Atomic Document Tamper Detection

#### verify-raw endpoint
- `POST /api/v1/notarize/verify-raw`: accepts raw document bytes (base64), computes SHA-256 server-side, verifies signature, and runs dimensional analysis — all in one atomic call
- Three verification levels: hash match (byte-exact), ML-DSA-65 signature (cryptographic), dimensional fingerprint (content/structure/tables/images/metadata)
- When hash doesn't match, searches registered documents by dimensional similarity and reports which dimensions changed
- Human-readable conclusion in Spanish for legal proceedings

#### ML-DSA-65 key persistence
- Signing key persisted to `STORAGE_PATH/signing_key_mldsa65.bin` on first generation
- Loaded from disk on subsequent restarts — DID and public key remain stable
- `MlDsaSigningProvider::export_key_bytes()` for key serialization

#### Production node redeployed
- EC2 node (`44.220.142.37`) rebuilt with all v0.17.x changes
- Verified: health, TSA, verify-raw, key persistence, structured logging

### Stats
- 2824 tests pass, clippy clean
- Node key: `did:goya:7a74e5fa59b71dfd` (ML-DSA-65, persistent)

---

## [0.17.0] — 2026-09-07

### Added — FEA Integrity Hardening + Production Node

#### Atomic signature verification
- `SignedEnvelope::verify()`: single-call structural + cryptographic verification
- `verify_notarization` endpoint re-verifies stored signature on every read
- `verify_document` rejects candidate fingerprints with inconsistent canonical_hash
- `NotarizationEntry` now persists `public_key` and `cades_der` (backwards compatible)

#### CAdES-T timestamping
- `sign_fea` and `notarize_pdf` now produce CAdES-T (timestamped) when TsaProvider configured
- TSA token obtained via `obtain_tsa_token()` and embedded in CAdES unsigned attributes
- CAdES envelope stored in `NotarizationEntry.cades_der` for later re-verification

#### CRL + CAdES verification on read
- `verify_notarization` re-verifies stored CAdES envelope via `verify_cades_with_context`
- CRL revocation check via `AppState.crl_store` during CAdES verification
- Timestamp token integrity validated on verify
- Response includes `signature_verified` and `cades_verified` fields

#### AWS production deployment
- EC2 t3.micro node (`44.220.142.37`) running Goya with ML-DSA-65
- TSA operational: RFC 3161, ML-DSA-65 signing, NTP-synced, policy OID `1.3.6.1.4.1.99999.1.1`
- CRL endpoint serving DER-encoded revocation lists
- OCSP responder active (DER + JSON)
- TLS with self-signed cert, RocksDB storage, structured JSON logging
- `deploy/aws/docker-compose.yml` + `deploy/aws/deploy.sh` for lifecycle management

### Stats
- 2824 tests pass, 0 failures, clippy clean
- 5 files changed for FEA hardening (+153/-24 lines)
- 4 files changed for CAdES-T + CRL wiring (+72/-14 lines)
- Node cost: ~$8.50/month

---

## [0.16.4] — 2026-09-07

### Added — Legal PDF Package

- `docs/pdf/legal/`: 87 PDFs generated from compliance, policy, FIPS, and research Markdown sources
- Automated AI-language cleanup applied before conversion (~40 substitutions: comprehensive→complete, robust→solid, leverage→use, etc.)
- Deduplicated 4 title collisions (EUDI v1/v2, API Reference, Benchmarks, Audit Package) — kept the more complete version of each
- Covers: EA-103 (17), FIPS 140-3 submission + pre-lab audit (19), ETSI/eIDAS policies (17), regulatory mappings (10), PQC crypto module (15), security operations (6), research papers (3)

---

## [0.16.3] — 2026-09-04

### Added — AI Disclosure & Dependency Audit

- `docs/compliance/AI-DISCLOSURE.md`: declaración formal de uso de IA generativa para due diligence
  - Herramienta, alcance, rol del autor humano, trazabilidad git
  - Posición legal por jurisdicción (Chile, EU, US, Estonia)
  - Metodología de desarrollo: IA como amplificador, contribución humana, replicabilidad
  - Auditoría completa de licencias de dependencias (cero copyleft fuerte)
  - Resumen ejecutivo para inversores

---

## [0.16.2] — 2026-09-03

### Added — CAVP Validation, Benchmarks, Certification Readiness

#### CAVP emulation (NIST ACVP official test vectors)
- `tests/cavp_validation.rs`: 117 NIST vectors verified byte-exact
- ML-DSA-65: keyGen (25), sigGen deterministic (30), sigVer pure mode (12)
- ML-KEM-768: keyGen (25), encapsulation (25)
- Vectors sourced from github.com/usnistgov/ACVP-Server
- Status: CAVP-READY (awaiting CMVP lab certification)

#### PQC comparative benchmarks
- `tests/pqc_benchmark.rs`: 5 benchmarks (sign/verify/keygen/hybrid/KEM)
- Ed25519: sign 9.1us, verify 19.6us
- ML-DSA-65: sign 90.5us (9.9x), verify 25.5us (1.3x)
- SLH-DSA-128s: sign 352ms (backup only)
- ML-KEM-768: encap 9.7us, decap 8.9us
- Hybrid (Ed25519+ML-DSA-65): sign 85.4us (6.8x), verify 64.2us (3.4x)

#### End-to-end throughput with real crypto
- `tests/e2e_throughput.rs`: full pipeline BFT + signing + execution
- Ed25519: 64,561 TPS | 1.55 ms/block
- ML-DSA-65: 10,260 TPS | 9.75 ms/block (6.3x overhead)
- Bottleneck: TX signing (83.2%), not verification (1.3x) nor execution (1.8%)
- Scaling: TPS plateaus at ~11,000 with 500 txs/block

#### Quantum papers mechanical verification
- `tests/quantum_cost_spec.rs`: 3 new tests
- Gidney & Ekera 2021: RSA-2048 = 20M qubits / 8h
- Google Quantum AI 2026: secp256k1 = <500K qubits / 9 min
- NIST IR 8547: classical deprecated 2030, prohibited 2035

#### Certification emulation
- `tests/certification_emulation.rs`: 16 tests emulating 3 certifications
- FIPS 140-3 (9 tests): FSM, self-tests, pre-init rejection, error terminal, zeroization, KAT, boundary, approved algorithms
- EA-103 Chile (3 tests): 17 docs present, standard references, 11 technical controls
- QTSP eIDAS (4 tests): PKI components, Art.45i 6 dimensions, PQC algorithms, EUDIW wallet

#### ETSI policy documents audit-ready
- EN 319 401 (TSP): 10 gaps closed — phantom doc IDs mapped, AUP created, GDPR section added, HR disciplinary process, version mismatch fixed
- EN 319 411 (CA): 14 gaps closed — cert extensions (AIA, CRLDP, SAN, EKU), QWAC profile completed, algorithm corrected, data protection added, financial responsibility quantified
- EN 319 421 (TSA): 15 gaps closed — HSM gap acknowledged, key crypto-period defined, revocation mechanism, personnel roles, audit log hash chain, RPO/RTO, termination procedure
- New: `docs/policy/ACCEPTABLE-USE-POLICY.md` (GOYA-AUP-001)

#### Technical paper
- `docs/paper/pqc-bft-performance.md` (English)
- `docs/paper/pqc-bft-rendimiento-es.md` + PDF (Spanish)
- First published data on PQC performance in production BFT consensus

### Stats
- 11,775 lines added across 20 files
- 117 NIST CAVP vectors, 16 certification tests, 5 benchmarks, 3 quantum paper tests
- 39 ETSI gaps closed across 3 policy documents
- All clippy clean, all tests pass

---

## [0.16.1] — 2026-09-02

### Added — PQC Testing & EU Compliance Documentation

Comprehensive property-based testing, stress testing, and mechanical verification
of BSI TR-02102-1, ANSSI hybrid mandate, and Mosca's theorem against live code.

#### Property-based testing (proptest)
- `src/fuzz_tests.rs`: 12 new proptest blocks (23 total)
- Block full roundtrip — all fields including PQC (signature, endorsements, QC, embedded entries)
- Transaction, IdentityRecord, Credential full roundtrip with all fields verified
- Endorsement roundtrip exercising custom `vec_hex` + `hash_hex` serializers
- `vec_hex`/`opt_vec_hex` edge cases: empty signatures, `Some(vec![])`
- Block with `QuorumCertificate` roundtrip (VoteMessage signatures, BftPhase)
- NotarizationEntry with biometric evidence roundtrip
- Block double roundtrip idempotency (JSON stability)
- Signature size x algorithm cross-validation (correct size passes, wrong size fails)
- Legacy JSON (missing `#[serde(default)]` fields) produces sane defaults
- Tampered JSON height detection
- SigningAlgorithm (5 variants) and HashAlgorithm (2 variants) enum roundtrip

#### Mempool stress test
- `tests/mempool_stress.rs`: 8 integration tests
- Backpressure: rejects at capacity, pool size invariant
- Concurrent add (10 threads x 100 txs): no lost transactions, no duplicates
- Drain under contention: adder + drainer simultaneous, conservation invariant
- Double-spend under concurrent load: 10 threads, shared sender, balance enforced
- Saturate-drain-refill cycle, drain more than available, remove under contention

#### BSI TR-02102-1 (2024) compliance
- `tests/eu_pqc_compliance.rs`: 5 BSI tests
- Algorithm classification: ML-DSA-65/SLH-DSA-128s = recommended, Ed25519/ECDSA = transitional, RSA = not recommended
- Primary algorithm meets NIST Level 3 (>=192-bit classical security)
- Key sizes verified against live keygen (Ed25519, ML-DSA-65, SLH-DSA-128s)
- Hash algorithm compliance (SHA-256 acceptable, SHA3-256 recommended)
- ML-KEM-768 encap/decap verified (pk=1184B, ct=1088B, ss=32B)

#### ANSSI hybrid mandate (2024) compliance
- `tests/eu_pqc_compliance.rs`: 5 ANSSI tests
- Hybrid signatures: Ed25519 primary + ML-DSA-65 secondary, `verify_hybrid` passes
- Corrupted primary rejected, corrupted secondary rejected
- Minimum NIST Level 3 for primary PQC
- Dual assumption independence (ECC + lattice + hash = 3 independent families)

#### Mosca's theorem — quantum migration urgency
- `tests/mosca_theorem.rs`: 5 tests
- 8 goya-ledger scenarios evaluated: FEA cert, CA root (17y), CA intermediate (12y), LexChain contract (17y), BFT vote (ephemeral), FES signature, notarized doc (27y perpetual), OID4VCI token (ephemeral)
- All long-term data (x >= 5y) PQC-protected where Mosca inequality holds (x+y > z)
- Urgency ranking: notarized docs > CA root > CA intermediate > LexChain > FES/FEA
- Ephemeral data (BFT votes, tokens) safe without PQC
- CRQC sensitivity analysis: 4 timelines (optimistic 2040, median 2035, pessimistic 2030, aggressive 2028) — zero unprotected long-term data under all scenarios

#### EA-103 documentation — BSI/ANSSI citations
- PS01 (Risk Management): BSI/ANSSI in R-11 quantum risk mitigation + references
- PS02 (Security Policy): BSI classification in crypto directives, ANSSI hybrid mandate in section 8.2, both in normative references
- PO01 (Certificate Policy): BSI/ANSSI in legal framework (section 2.5) + references (section 13)
- PS06 (Key Management): BSI classification per algorithm in selection criteria (section 6.1.6), ANSSI hybrid mandate paragraph, both in framework (section 3) + references (section 14)
- PSC Accreditation Checklist: BSI/ANSSI alignment noted in key management status

### Stats
- 46 new tests (23 proptest + 8 mempool + 10 EU PQC + 5 Mosca)
- 14 BSI TR-02102-1 citations + 10 ANSSI Avis PQC citations across 5 EA-103 documents
- Clippy clean, all pre-push gates pass

---

## [0.14.1] — 2026-09-01

### Added — EU TSP Readiness

EUDIW interop, legal docs, Smart-ID identity verification, and authorization code flow.

#### EUDIW Conformance E2E
- `scripts/eudiw-conformance-e2e.sh` — 53 assertions across 20 phases
- Covers OID4VCI 1.0 Final (metadata, token, nonce, credential offer, SD-JWT + mdoc issuance)
- Covers OID4VP 1.0 Final (RP registration, DCQL requests, cross-device QR, presentation_definition rejection)
- Fix: `NonceStore`/`StatusListStore`/`VpRequestStore` shared across Actix workers (was per-worker)

#### Legal Documents (live at goya-docs.fly.dev)
- `cps.html` — Certificate Practice Statement (ETSI EN 319 411-1 / RFC 3647)
- `privacy.html` — Privacy Policy (GDPR Art. 13-14, Estonian DPA as supervisory authority)
- `terms.html` — Subscriber Agreement (eIDAS Art. 13, €100K liability cap for AdES)
- Docs Dockerfile updated to serve all 6 pages

#### Smart-ID Identity Verification (SK ID Solutions)
- `SmartIdVerifier` — IdentityVerificationProvider for Estonian eID (Smart-ID RP API v2)
- Demo (`SMART_ID_UUID=demo`) and production constructors
- ETSI PNO identifier format, LoA mapping (QUALIFIED→High, ADVANCED→Substantial)
- `POST /api/v1/identity/verify` — calls external IdP via `web::block`, returns proofing + verification result
- `identity_verifier` field on `AppState`, wired via `SMART_ID_UUID` / `SMART_ID_NAME` env vars
- Fallback: `SimulatedIdentityVerifier` when no env var set

#### Authorization Code Flow (OID4VCI)
- `POST /as/par` — Pushed Authorization Request (RFC 9126) with PKCE S256
- `GET /authorize?request_uri=...` — issues authorization code, 302 redirect
- Token endpoint now requires `code_verifier` for `authorization_code` grant
- `AuthorizationStore` shared across workers, 600s session TTL, auto-eviction
- Both grants supported: `pre-authorized_code` (QR offer) and `authorization_code` (wallet-initiated)

### Stats
- 56 OID4VCI tests, 8 RA handler tests, 49 RA unit tests, 53 E2E conformance assertions
- Clippy clean, all pre-push gates pass

---

## [0.14.0] — 2026-08-31

### Added — EU Compliance Gaps 1-9

Systematic closure of 9 out of 11 eIDAS 2.0 / NIS2 / CRA compliance gaps.
Remaining gaps 10-11 (QSCD hardware + QTSP certification) are process/procurement.

#### Gap 1 — CRA Vulnerability Disclosure (EU 2024/2847 Art. 11)
- `SECURITY.md` expanded: vulnerability reporting email, PGP key, response SLA (72h initial, 24h for actively exploited), ENISA notification procedure
- `GET /.well-known/security.txt` endpoint per RFC 9116 (`src/api/handlers/security_txt.rs`)
- Registered in root-level router (`src/api_legacy.rs`)

#### Gap 2 — Formal SBOM (NIS2 Art. 21, CRA Art. 13)
- `scripts/generate-sbom.sh` — CycloneDX 1.5 SBOM generation via `cargo-cyclonedx`
- `sbom.cdx.json` — 921 components with versions and licenses
- Dockerfile updated: copies SBOM into `/app/` for distribution

#### Gap 3 — Relying Party Registration (CIR 2025/848)
- `RelyingParty` struct + `VpRequestStore.relying_parties` registry
- `POST /api/v1/oid4vp/rp` — register a relying party
- `GET /api/v1/oid4vp/rp` — list registered RPs
- `POST /api/v1/oid4vp/request` returns 403 `UNREGISTERED_RP` for unknown RPs
- RP metadata (`client_name`, `purpose`, `data_requested`) disclosed in presentation requests
- 5 new tests

#### Gap 4 — Wallet Trust Evidence (ARF v2.0 Topic 38)
- `verify_wte()` — validates `typ=wte+jwt`, `cnf` binding, expiry, iat freshness, signature
- `wallet_trust_evidence` field on `TokenRequest`
- Token endpoint validates WTE alongside existing WIA
- `WalletProviderRegistry` shared for WIA + WTE signature verification

#### Gap 5 — External Identity Verification (eIDAS Art. 26(b))
- `IdentityVerificationProvider` trait — pluggable external IdP (`src/identity/ra.rs`)
- `SimulatedIdentityVerifier` for testing (approves valid national IDs)
- `RaStore::submit_and_verify()` — calls external IdP and links verified identity to DID
- `VerificationResult` with `verified`, `provider_name`, `loa`, `external_reference`
- Multi-jurisdiction: Chile (RUT), UAE (Emirates ID), EU (national ID)
- 8 new tests
- `ELECTRONIC-SIGNATURE-COMPLIANCE.md` Art. 26(b) updated

#### Gap 6 — NIS2 Security Management (NIS2 Art. 21)
- `docs/compliance/NIS2-MAPPING.md` — maps all 10 Art. 21(2) categories to Goya controls
- 39 requirements assessed, 35 covered (90%), 4 organizational gaps documented
- `INCIDENT-RESPONSE-PLAN.md` updated with NIS2 Art. 23 notification SLAs (24h/72h)
- EN 319 401 v3.2.1 clause references per category

#### Gap 7 — Qualified Electronic Ledger (eIDAS 2.0 Art. 45i)
- `docs/compliance/CIR-2025-2531-MAPPING.md` — maps all 8 Art. 45i dimensions
- Sequential ordering, time stamping, tamper evidence, data origin authentication, unique identifiers, immutability, consensus, auditability — all covered with file paths and evidence
- Zero technical gaps; qualified status blocked only by QTSP certification

#### Gap 8 — QERDS (eIDAS Art. 44, EN 319 521/522)
- `DeliveryReceipt` struct with `send_tsa_token` + `receipt_tsa_token`
- `ContractState::Delivered` — new state after `FullySigned`/`Notarized`
- `deliver()` — creates TSA-timestamped proof of sending per party
- `acknowledge_delivery()` — creates TSA-timestamped proof of receipt
- State transitions: all parties delivered → `Delivered`; `archive()` accepts `Delivered`
- 8 new tests including full ERDS lifecycle

#### Gap 9 — Qualified Archiving (eIDAS 2.0 Art. 45g)
- `PreservationRecord` struct with original/new algorithm, signature, TSA token
- `preserve_contract()` — re-signs with non-deprecated algorithm + TSA timestamp
- `preserve_expiring()` — sweeps contracts approaching `AlgorithmPolicy` deprecation deadlines
- Idempotent: skips already-preserved contracts
- 5 new tests

#### Tracking document
- `docs/compliance/EU-COMPLIANCE-GAPS.md` — master gap tracker with 11 gaps, execution order, effort estimates

### Stats
- 2755 library tests pass (13 new in LexChain ERDS/archival)
- 7 new files, 16 modified files
- Clippy clean (`cargo clippy -- -D warnings`)

---

## [0.13.3] — 2026-08-27

### Changed — Startup Chile Build pitch rewrite (data-verified)

Complete rewrite of `pitch.html` based on advisor pushback and market research.

#### Claims removed (debunked)
- ~~"$5K-50K CLP por firma"~~ — FEA costs $15K-$45K CLP/year with unlimited signatures
- ~~"USD $120M mercado firma electrónica Chile"~~ — no public source; nearest is DTM Chile $124.4M (Grand View Research) which includes workflow, payments, docs
- ~~"10x más barata"~~ — misleading price comparison
- ~~"250.000 pymes sin acceso a firma electrónica"~~ — no study quantifies FEA adoption in Chilean SMEs
- ~~"más de $1.000.000 CLP mensuales en firmas"~~ — false arithmetic based on wrong per-signature cost

#### New thesis
- Core: "En el mundo digital no distingues real de falso. Goya agrega la prueba matemática que viaja con el documento."
- Verification independence (no PSC online dependency, no Adobe dependency, no certificate expiry dependency)
- Counterparty signs via link without owning FEA

#### Verified data now in pitch
- 1,154 OIV designated by ANCI (Res. 87/2025 + Res. 187/2026) — Ley 21.663
- 468 notarías must digitalize by Oct 2026 — Ley 21.772
- 42 fintechs registered, 37 authorized by CMF — Ley 21.521
- 10 PSC acreditados, none with PQC — Entidad Acreditadora
- FEA real costs: $15K-$45K CLP/year, single-use $2.5K-$4.5K — ChileAtiende, Acepta, E-certchile
- Fines up to 40,000 UTM (~$2,640M CLP) for OIV — Ley 21.663
- PSC certification: "en trámite" (honest)

#### Competitor table reframed
- E-certchile/Acepta: "servicio probado, años de trayectoria" (respectful) + "verificación depende del PSC, criptografía clásica"
- DocuSign: "no cumple Ley 19.799 como FEA, $10-$45 USD por sobre"
- TOC: "solo FES, sin verificación independiente"

#### Video pitch script rewritten
- Opens with "en el mundo digital no distingues real de falso" (advisor's 2D/3D framing)
- Market section cites 1,154 OIV + 468 notarías + 42 fintechs (regulatory demand, not speculative)
- Closes with "certificarnos como PSC y validar con 5 pilotos"

### Stats
- 1 file changed, 118 insertions, 156 deletions
- Site live at `goya-docs.fly.dev/pitch.html`

---

## [0.13.2] — 2026-08-26

### Added — Startup Chile & investor documentation site

Commercial landing, Startup Chile Build pitch, and investor brief deployed to `goya-docs.fly.dev`.

#### Landing page (`index.html`)
- Commercial product page targeting Chilean SMEs
- Hero with $99/month pricing, feature grid, 4-step flow, competitor comparison table
- Compliance tags (Ley 19.799, DS 181, Ley 21.663)
- CTA links to `goya-explorer.fly.dev/signup`
- Nav links to app and investor brief
- Dark/light theme via `prefers-color-scheme`

#### Startup Chile Build pitch (`pitch.html`)
- 10 sections aligned to CORFO Build evaluation rubric (5 weighted criteria)
- Problem/solution framed for Chilean market (250K SMEs, 10x price reduction)
- Fund allocation: $15M CLP (33% PSC certification, 27% pilots, 17% infra, 10% legal, 13% GTM)
- 4-month roadmap with KPIs (5 pilots, 50 contracts, $500K CLP MRR)
- 90-second video pitch script
- Links to live app and API

#### Investor brief (`investors.html`)
- ES/EN toggle (client-side, no page reload)
- 10 slides: thesis, why now, market, product, business model, competition, GTM, team, the ask, contact
- Unit economics: LTV $2.4K–$54K, CAC $200–$500, >85% gross margins
- Timeline: 5 pilots Q4 2026, PSC cert Q1 2027, 50 customers Q2–Q3 2027, LATAM Q4 2027
- Projections: 50 customers month 12, $500K ARR month 18

#### Infrastructure
- Dockerfile updated: serves 3 HTML files via nginx:alpine
- All pages cross-linked: landing ↔ app ↔ investors ↔ pitch

### Stats
- 3 new HTML files, 1 updated Dockerfile
- Site live at `goya-docs.fly.dev`

---

## [0.13.1] — 2026-08-25

### Added — Formal Verification (Lean 4)

Machine-checked proofs in `formal/` — Lean 4.33 + Mathlib.

#### FIPS 140-3 State Machine (`Formal.FipsStateMachine`)
- Error is terminal (no outgoing transitions)
- Approved only reachable through SelfTesting
- Crypto requires Approved state
- Unique initialization path: Uninitialized → SelfTesting → Approved
- Approved is absorbing (no degradation)

#### BFT Consensus Safety (`Formal.BftSafety`)
- **`no_fork`**: two quorums of ≥ 2f+1 from 3f+1 validators overlap by ≥ f+1 — at least one honest node in common, making conflicting decisions impossible
- Proven for general f, instantiated for n=4 (goya default) and n=7

#### Quarantine Correctness (`Formal.QuarantineCorrectness`)
- PQC signature prevents quarantine (ML-DSA-65 not in classical list)
- Ed25519-only contracts ARE quarantined
- PQC and classical algorithm sets are disjoint

#### Lattice Algebra (`Formal.Lattice.*`) — Mathlib-powered
- `Zq`: Z/8380417Z defined via `ZMod`, q proven prime by `native_decide`
- `Rq`: R_q = Z_q[X]/(X^512+1) as `AdjoinRoot`, `CommRing` instance
- `ModuleLWE`: Module-LWE types (public matrix A ∈ R_q^{6×5}, secret/public vectors) + hardness axiom

#### ML-DSA-65 Scheme (`Formal.Lattice.MlDsa`)
- **KeyGen**: t = A·s₁ + s₂; `keygen_public_key_is_mlwe` proves pk is a Module-LWE instance
- **Sign**: z = y + c·s₁; `sign_response_structure` proves response form
- **Verify**: check A·z - c·t = w'; `verify_correctness` proves Az - ct = Ay - cs₂
- Hash oracles axiomatized (expandA, hashToChallenge, sampleSecret, sampleMaskingVec)

#### EUF-CMA Security Reduction (`Formal.Lattice.SecurityGame`)
- EUF-CMA game: adversary with signing oracle produces forgery
- SelfTargetMSIS problem formalized (following Barbosa et al., CRYPTO 2023)
- **`eufcma_implies_stmsis`**: any valid forgery IS a SelfTargetMSIS solution
- Reduction chain: EUF-CMA → NMA → SelfTargetMSIS + MLWE
- CMA-to-NMA reduction axiomatized (the gap found and fixed in CRYPTO 2023)
- PQC and classical algorithm sets are disjoint

### Added — Cryptographic Agility Protocol (`AlgorithmPolicy`)

First-class algorithm lifecycle management — deprecation with deadlines.

- `AlgorithmPolicy::new(node_algo)` — node announces supported algorithms
- `deprecate(algo, time, reject_after, reason)` — mark algorithm for sunset with deadline
- `is_accepted(algo, time)` / `is_rejected(algo, time)` — policy enforcement
- `active_algorithms(time)` — list non-rejected algorithms at a given time
- `status_map(time)` — full status: active, accepted, deprecated, rejected
- Guards: cannot deprecate node's active algorithm, no double deprecation, deadline must be future
- 7 unit tests covering all policy states and transitions

### Added — Algorithm Death Day E2E (`scripts/algorithm-death-day-e2e.sh`)

End-to-end smoke test against a live goya-ledger node via HTTP API:
- 14 assertions, 0 failures
- Creates 4 identities (2 Ed25519 32B, 2 PQC 1952B) via `POST /store/identities`
- Deploys 2 contracts (Ed25519-only NDA + PQC service agreement) via `POST /lexchain/deploy`
- Retrieves contracts by ID, verifies party count and state
- Verifies identity persistence and PQC key sizes (3904 hex chars = 1952B)
- Health check before and after scenario
- Works against local node or remote (pass URL as arg)

### Added — Quantum Threat Simulator (`tests/quantum_threat_sim.rs`)

Unified attack harness — 10 tests across 6 attack vectors:

#### 1. Side-channel timing analysis
- ML-DSA-65 sign/verify coefficient of variation measured
- Ed25519 vs ML-DSA-65 performance ratio benchmarked
- Rejection sampling variance accounted for (Fiat-Shamir with aborts)

#### 2. Fault injection vs FIPS state machine
- Error state blocks ALL crypto operations (keygen, sign, verify, hash, KEM)
- Uninitialized state blocks keygen
- Recovery after reinitialization verified

#### 3. Lattice parameter security
- ML-DSA-65: BKZ-β=625, 192-bit classical, 143-bit quantum → INFEASIBLE
- ML-KEM-768: BKZ-β=630, 192-bit classical, 143-bit quantum → INFEASIBLE

#### 4. Grover effective security
- SHA3-256: 128-bit post-quantum (SECURE)
- AES-256-GCM: 128-bit post-quantum (SECURE)
- SLH-DSA-128s: 64-bit post-quantum (REDUCED but viable)
- Output sizes verified against live code

#### 5. Cross-algorithm forgery resistance
- Ed25519 signature rejected by ML-DSA-65 verifier and vice versa
- Size mismatch verified (64B vs 3309B)

#### 6. Unified report
- All vectors aggregated in single pass with verdict

### Added — Quantum Cost Specification

Exact qubit bounds for attacking every cryptographic primitive in goya-ledger
(`tests/quantum_cost_spec.rs`).

| Primitive | Quantum Security | Logical Qubits | Gate Ops | Wall-clock (1 GHz) |
|---|---|---|---|---|
| Ed25519 | **0 bits** (Shor) | 2,330 | 2^37 | 4.4 days |
| SLH-DSA-128s | 64 bits (Grover) | 6,400 | 2^64 | 585 years |
| ML-DSA-65 | **143 bits** (BKZ) | 16,000 | 2^143 | 3.5×10^25 years |
| ML-KEM-768 | **143 bits** (BKZ) | 15,000 | 2^143 | 3.5×10^25 years |
| SHA3-256 | 128 bits (Grover) | 7,680 | 2^128 | 1.1×10^22 years |
| AES-256-GCM | 128 bits (Grover) | 6,681 | 2^128 | 1.1×10^22 years |

- Parameter sizes verified against live code (Ed25519 32/64B, ML-DSA 1952/3309B, SLH-DSA 32/7856B, ML-KEM 1184/1088/32B)
- Composition analysis: primary system security 143-bit quantum (lattice), backup 64-bit (hash-based, independent assumption)
- Hardware projection: IBM 2035 roadmap ~100 logical qubits — Ed25519 needs 2330, ML-DSA-65 needs 16000

### Added — Algorithm Death Day test suite

Quantum threat simulation: 22 integration tests proving goya-ledger survives
complete Ed25519 compromise with zero block loss and automatic PQC migration.

#### Phase 1 — Detection
- Dual signing (Ed25519 + ML-DSA-65) detects forged Ed25519 signatures
- Secondary PQC signature catches tampered blocks

#### Phase 2 — Containment
- Contracts signed only with Ed25519 are quarantined
- Contracts with at least one PQC signature survive
- Classical algorithm detection via `SigningAlgorithm::is_classical()`

#### Phase 3 — Migration
- 50 identities migrated Ed25519 → ML-DSA-65 in-place
- Mining continues uninterrupted after algorithm switch
- LexChain operates under PQC-only signing

#### Phase 4 — Post-mortem verification
- All dual-signed pre-compromise blocks verified via PQC secondary signature
- PQC contract signatures remain valid indefinitely
- Full end-to-end scenario: 20 blocks, 2 contracts, 0 blocks lost, 0 consensus interruption

#### Phase 5 — Adversarial BFT consensus
- Forged Ed25519 vote impersonating a validator → `InvalidSignature` rejection
- Unknown attacker with valid ML-DSA-65 key → `UnknownVoter` rejection
- Forged QC (1 legit + 2 Ed25519-forged votes) → `InvalidSignature` on validation
- 4-node ML-DSA-65 network decides 2 rounds despite active attacker injection

#### Phase 6 — Block injection attacks
- Proposal from non-leader node → silently ignored by all honest nodes
- Proposal with forged `justify_qc` (Ed25519-signed votes) → rejected by `validate_received_qc`
- Malicious leader forging votes from other validators → cannot reach quorum (invalid signatures)
- Network recovers after malicious leader timeout, continues deciding subsequent rounds

#### Phase 7 — Network partition during migration
- 2v2 partition: neither side reaches quorum (need 3/4), both stall
- Partition heals: all 4 nodes rejoin, consensus resumes immediately
- Migration during partition: isolated nodes migrate identity while offline, rejoin and decide
- 3v1 partition: majority side (3 nodes) reaches quorum and decides, isolated node stays behind

#### Atomic identity migration (`migrate_identity`, `resolve_identity`)
- `KeyManager::rotate_algorithm(new_algo, timestamp)` — cross-algorithm key rotation (Ed25519 → ML-DSA-65)
- `migrate_identity(store, old_did, new_algo, timestamp)` — atomic: marks old DID as "migrated", creates new DID with `migrated_from` link
- `resolve_identity(store, did)` — follows migration chain, returns the active identity
- `IdentityRecord.migrated_from: Option<String>` — links new DID to old DID
- 50-identity batch migration tested with full verification of old→new chain

#### Contract quarantine (`quarantine_classical_contracts`)
- `ContractState::Quarantined` added to LexChain state machine
- `quarantine_classical_contracts(store, compromised_algos)` scans and quarantines contracts signed exclusively with compromised algorithms
- Contracts with at least one PQC signature are preserved

### Fixed — Block signing payload mismatch

- `MiningService::mine_block()` signed an ad-hoc format string (`height:parent:merkle:txids`), but `verify_block_secondary_signature()` verified against `block_hash_for_signing()` (`sha256(height||parent||merkle)`) — signatures always failed verification
- `mine_block()` now builds the block first, then signs `block_hash_for_signing(&block)` — same canonical hash used by all ordering/verification functions
- Algorithm Death Day tests now use `verify_block_secondary_signature` directly instead of workaround

### Fixed — PQC TLS default assertion in integration tests

- `tls_pqc_env_toggle_works` and `tls_pqc_flag_controls_provider_selection` asserted PQC KEM disabled by default — contradicted implementation where `TLS_PQC_KEM` defaults to `true` (PQC enabled)

### Stats
- 2722 lib tests, 150 PQC tests, 84 integration tests — 0 failures
- fmt + clippy clean

---

## [0.13.0] — 2026-08-18

### Added — Bulk FES sign & verify, SDK, FES/FEA end-to-end, goya-sign CLI

Production-ready document signing and verification at scale.

#### Bulk FES Signing (`POST /sign/fes/bulk`)
- Server-side signing: upload up to 100 files (base64), node hashes + signs each
- SHA-256 fingerprint, Ed25519/ML-DSA-65 signature, optional TSA timestamp per file
- Duplicate detection, invalid base64 handling, per-file status
- PDF fingerprint stored in metadata for dimensional analysis

#### Bulk FES Verification (`POST /verify/fes/bulk`)
- Verify up to 100 items per request (file base64 or content_hash)
- 4 statuses: `verified` (intact), `altered` (modified, shows who signed original), `not_found`, `error`
- `original_hash` field enables alteration detection against signed original
- PDF dimensional analysis (content, structure, metadata) when fingerprint available
- Reports: original signer, timestamp, algorithm, match_ratio, per-dimension verdict

#### FES End-to-End (`scripts/try-fes.sh`)
- Full lifecycle: create DIDs → deploy NDA → sign both parties (Ed25519) → verify
- Runs against local or remote node

#### FEA End-to-End (`scripts/try-fea.sh`)
- Power of Attorney with ML-DSA-65 (FIPS 204) + biometric evidence
- Fingerprint + facial recognition biometrics
- Runs against local or remote node

#### goya-sign CLI (`src/bin/goya_sign.rs`)
- `goya-sign keygen ed25519` / `goya-sign keygen ml-dsa-65`
- `goya-sign sign ed25519 <sk> <payload>` / `goya-sign sign ml-dsa-65 <sk> <payload>`
- Enables client-side PQC operations without external dependencies

#### TypeScript SDK (`sdk/`)
- `npm install goya-sdk`
- `GoyaClient`: deploy, signWithKeypair, sign, getContract, listContracts, listTemplates, registerIdentity
- `generateKeypair()`: Ed25519 via @noble/ed25519 (pure JS)
- 12 lines from zero to signed contract
- Proven end-to-end against running node

#### Documentation (`docs/`)
- Bilingual EN/ES landing page (Plus Jakarta Sans, B&W, dark/light)
- Live at goya-docs.fly.dev
- Sections: Stack, LexChain, API (with Bulk FES), SDK, Compliance, Use Cases, PQC Comparison

#### Infrastructure
- LexChainStore shares gateway BlockStore backend (DID verification works cross-module)
- 280 API endpoints, 2721 tests, 0 failures

---

## [0.12.3] — 2026-08-18

### Added — LexChain templates + webhooks

#### Contract Templates
- 3 built-in templates: `nda`, `service_agreement`, `power_of_attorney`
- `deploy_from_template()` — instantiate with role→DID map + payload
- `DeployRequest` enum: accepts either full `ContractDefinition` or `{template, parties, payload}`
- `register_template()` for custom templates at runtime
- `GET /api/v1/lexchain/templates` — list available templates
- `power_of_attorney` enforces `SignatureLevel::Advanced` (FEA + biometric)

#### JSON deploy from template
```json
{
  "template": "nda",
  "parties": {"discloser": "did:goya:alice", "recipient": "did:goya:bob"},
  "payload": {"scope": "project X"}
}
```

#### Webhooks
- `webhook_url` field in `ContractDefinition` — fire-and-forget POST on state changes
- Events fired: `deployed`, `signed`, `notarized`
- `WebhookEvent` payload: contract_id, event, state, timestamp
- Non-blocking via `tokio::spawn`, 10s timeout, failures logged

### Stats
- 2721 lib tests passed, 0 failed (28 LexChain tests, 8 new)
- fmt + clippy clean

---

## [0.12.2] — 2026-08-18

### Added — LexChain contract deadlines and expiry

Contracts can now expire if not fully signed within a deadline.

- `deadline_secs` field in `ContractDefinition` — seconds from deploy until expiry (`null` = no deadline)
- `Expired` state in `ContractState` — terminal, no further signatures accepted
- `sign()` checks expiry before accepting — auto-transitions to `Expired` and rejects
- `expire_pending()` — batch sweep function to expire all overdue contracts
- `is_expired(now)` on `LexContract` — pure check, no side effects

#### JSON example
```json
{
  "type": "service_agreement",
  "parties": [...],
  "payload": {...},
  "deadline_secs": 259200
}
```
259200 = 72 hours. After 72h without all signatures, the contract expires.

### Stats
- 2713 lib tests passed, 0 failed (20 LexChain tests, 7 new timeout tests)
- fmt + clippy clean

---

## [0.12.1] — 2026-08-18

### Changed — LexChain hardened: persistence, archival, DID verification

Three priority-high gaps closed. LexChain is now production-grade.

#### 1. RocksDB persistence
- `LexChainStore` now wraps `Arc<dyn BlockStore>` (was in-memory HashMap)
- `BlockStore` trait extended with `write_lexcontract()`, `read_lexcontract()`, `list_lexcontracts()`
- `MemoryStore` and `RocksDbBlockStore` both implement LexChain persistence
- New CF `lexcontracts` in RocksDB column families
- `LexChainStore::with_backend()` for custom storage backend injection

#### 2. On-chain archival
- `archive()` writes a `Transaction` to `BlockStore` with id `lxc-archive:{contract_id}`
- Transaction records `input_did` (first party), `output_recipient: "lexchain:archive"`
- `block_height` set from `get_latest_height()` — contract is anchored to the chain

#### 3. DID verification
- `sign()` validates that `req.did` exists in the identity store before accepting the signature
- Unregistered DIDs are rejected with `LexChainError::DidNotRegistered`
- Prevents spoofing: can't sign as a DID that was never registered on-chain

### Stats
- 2706 lib tests passed, 0 failed (13 LexChain tests)
- fmt + clippy clean

---

## [0.12.0] — 2026-08-18

### Added — Goya LexChain v1: legal contract engine

Goya's equivalent of Ethereum Smart Contracts — but for legal instruments.
Developers define contract flows in JSON; LexChain executes them with
FES/FEA signatures, DID identity, TSA timestamps, and PQC cryptography.

#### Engine (`src/lexchain/`)
- **State machine**: PendingSignatures → FullySigned → Notarized → Archived
- `deploy()` — validate definition, create contract, assign party states
- `sign()` — validate FES/FEA constraints, verify cryptographic signature, advance state
- `notarize()` — TSA timestamp (RFC 3161) over contract content hash
- `archive()` — mark contract with on-chain block height
- Auto-notarization: when all parties sign and `require_notarization: true`, TSA fires automatically

#### API (`/api/v1/lexchain/`)
- `POST /lexchain/deploy` — deploy contract from JSON definition, returns contract_id
- `POST /lexchain/{id}/sign` — party signs with DID + signature + optional biometric evidence
- `GET /lexchain/{id}` — contract state + all cryptographic proofs
- `GET /lexchain` — list all contracts
- ACL enforced on all endpoints

#### Contract JSON Schema
```json
{
  "type": "service_agreement",
  "parties": [
    {"role": "provider", "did": "did:goya:...", "signature_level": "advanced"},
    {"role": "client", "did": "did:goya:...", "signature_level": "simple"}
  ],
  "payload": {"terms": "..."},
  "require_notarization": true
}
```

#### What LexChain orchestrates (existing infrastructure, zero new crypto)
- FES (Firma Electrónica Simple) — Ed25519/ML-DSA-65
- FEA (Firma Electrónica Avanzada) — ML-DSA-65 + biometric evidence
- DID identity verification
- TSA RFC 3161 timestamps with PQC signatures
- SignedEnvelope + CAdES DER proofs
- Signature consistency validation (algorithm ↔ key size ↔ level)

### Stats
- 2702 lib tests passed, 0 failed
- 9 new LexChain engine tests (deploy, sign, notarize, archive, multi-party, FEA+PQC)
- fmt + clippy clean

---

## [0.11.5] — 2026-08-18

### Fixed — FIPS 140-3 audit readiness (5 findings resolved)

Closes all findings that would fail a CMVP/FIPS 140-3 lab audit.

#### 1. SAFETY comments on all unsafe FFI blocks
- `mldsa.rs`: 3 unsafe blocks (keypair_from_seed, sign_internal_derand, sign_external_derand)
- `mlkem.rs`: 2 unsafe blocks (keypair_derand, enc_derand)
- `types.rs`: already had SAFETY comments (mlock/VirtualLock)

#### 2. assert_eq! → Result in production crypto (no more panics)
- `generate_keypair_from_seed()` returns `Result<MldsaKeyPair, CryptoError>` (was panic)
- `sign_message_derand()` / `sign_message_external_derand()` return `Err` on siglen mismatch (was assert)
- FFI failure transitions to `Error` state (FIPS 140-3 fail-closed) instead of panicking

#### 3. Cryptographic boundary enforced — zero direct ed25519_dalek imports
- All `ed25519_dalek::*` in `src/` replaced with `pqc_crypto_module::legacy::ed25519::*`
- 14 files updated across signing, ordering, channels, consensus, bin

#### 4. ML-DSA production path through module internals (not legacy::mldsa_raw)
- `MlDsaSigningProvider` rewritten over `pqc_crypto_module::types` + `pqc_crypto_module::mldsa`
- `verify_mldsa65()` uses `pqc_crypto_module::mldsa::verify_signature_raw` (not legacy)
- `ValidatorRegistry::verify_vote()` uses `pqc_crypto_module::mldsa` (not legacy)
- `legacy::mldsa_raw` no longer used in any production path

#### 5. SECURITY_POLICY §2 updated to match code
- Boundary description now accurately reflects api.rs + mldsa/mlkem/slhdsa internal modules
- Documents legacy module blocking and `approved-only` feature gate

### Stats
- 2693 lib tests + 150 pqc_crypto_module tests = 2843 total, 0 failed
- fmt + clippy clean

---

## [0.11.4] — 2026-08-18

### Changed — TLS PQC key exchange enabled by default

- `TLS_PQC_KEM` now defaults to `true` — X25519+ML-KEM-768 hybrid key exchange active out of the box
- Set `TLS_PQC_KEM=false` to fall back to classical X25519-only
- No production nodes exist yet, so no backward-compat risk — first deploy will be PQC-native

---

## [0.11.3] — 2026-08-18

### Changed — PQC integration gaps closed (algorithm-agnostic paths)

Eliminated all remaining Ed25519-hardcoded paths. Every signing subsystem now
dispatches through `SigningProvider` trait — Ed25519, ML-DSA-65, SLH-DSA, ES256.

#### Key Management (`src/identity/keys.rs`)
- `KeyManager` rewritten over `Box<dyn SigningProvider>` (was `ed25519_dalek::SigningKey`)
- `KeyManager::with_algorithm(SigningAlgorithm, timestamp)` — construct with any supported algo
- `KeyManager::new()` preserved for backward compat (defaults to Ed25519)
- `rotate_key()` generates keypair of the same algorithm as the active key
- `PublicKeyInfo` now tracks `algorithm` per key (was `[u8; 32]` fixed)

#### HSM (`src/identity/hsm.rs`)
- `HsmConfig.algorithm` field — reads from `HSM_KEY_ALGORITHM` env var (`ml-dsa-65` / `ed25519`)
- `HsmSigningProvider.algorithm()` reads from config (was hardcoded Ed25519)
- `SimulatedHsmProvider` uses `Box<dyn SigningProvider>` internally — supports Ed25519 and ML-DSA-65

#### Dual Signing Integration (`src/mining.rs`, `src/ordering/mod.rs`)
- `MiningService.secondary_signer` — optional second `SigningProvider` for PQC migration
- `mine_block()` fills `Block.secondary_signature` + `secondary_signature_algorithm` when present
- `verify_block_secondary_signature()` — new verification function for dual-signed blocks

#### Identity API (`src/api/handlers/identity.rs`)
- `create_identity` reads algorithm from node's `AppState.signing_provider` (was always Ed25519)

#### Test Alignment
- Equivocation detector tests: Ed25519 literals → MlDsa65 (production code was already algo-agnostic)
- Light client test helper: Ed25519 → ML-DSA-65

### Stats
- 2695 lib tests passed, 0 failed
- fmt + clippy clean

---

## [0.11.2] — 2026-08-17

### Added — SLH-DSA-SHAKE-128s (FIPS 205) hash-based backup signatures

First blockchain DLT to implement all three NIST PQC signature standards.

#### Crypto Module
- **`slhdsa.rs`** — SLH-DSA-SHAKE-128s keygen, sign, verify (pk=32B, sk=64B, sig=7856B)
- Power-on self-test KAT for SLH-DSA added to `self_tests::run_all()`
- Public API: `generate_slhdsa_keypair()`, `slhdsa_sign()`, `slhdsa_verify()`

#### DLT Integration
- `SigningAlgorithm::SlhDsa128s` variant in signing enum
- `is_post_quantum()` returns `true` for SLH-DSA (PQC policy enforcement)
- Signature consistency validation: 7856-byte size check
- Signature verification dispatch via `pqc_crypto_module::slhdsa`
- OID `2.16.840.1.101.3.4.3.20` (id-slh-dsa-shake-128s) in CAdES, OCSP, TSA, XAdES
- COSE algorithm ID `-49` in mdoc issuer auth
- JWT algorithm `"SLH-DSA-SHAKE-128s"` in SD-JWT
- PAdES sub_filter support

### Stats
- 2688 lib tests passed, 0 failed
- `pqc_crypto_module`: 150 tests (42 unit + 108 integration)

---

## [0.11.1] — 2026-08-17

### Added — PQC Certification Gauntlet (CMVP-ready)

154 PQC-specific tests + 4 fuzz targets. 256 NIST/Wycheproof vectors verified byte-exact.

#### NIST ACVP Test Vectors (official, from NIST ACVP-Server)
- **ML-DSA-65 keyGen** — 3 vectors, deterministic keygen from seed via custom `keypair_from_seed` C FFI (`csrc/keypair_from_seed.c`)
- **ML-DSA-65 sigGen internal** — 3 vectors, deterministic signing via `sign_internal_derand` C FFI (`csrc/acvp_derand.c`)
- **ML-DSA-65 sigGen external** — 3 vectors with context, via `sign_external_derand` C FFI
- **ML-DSA-65 sigGen deterministic** — 3 vectors (rnd=zeros)
- **ML-DSA-65 sigVer** — 10 NIST ACVP vectors (1 valid, 9 invalid, external mode with context)
- **ML-KEM-768 keyGen** — 3 vectors via PQClean `keypair_derand` FFI
- **ML-KEM-768 encapsulation** — 3 vectors via PQClean `enc_derand` FFI
- **ML-KEM-768 decapsulation** — 5 vectors via standard `decapsulate` API
- **SHA3-256 KAT** — 3 FIPS 202 vectors

#### C2SP Wycheproof (community standard)
- **ML-DSA-65 sigVer full suite** — 210/210 vectors (79 valid, 131 invalid), 25 groups including wrong-size keys, modified signatures, invalid hints, infinity norm violations

#### Adversarial Gauntlet (`tests/pqc_gauntlet.rs`)
- Bit-level signature corruption sweep (100+ positions)
- ML-DSA randomized signing proof (FIPS 204 §5.2)
- Signature malleability resistance (complement, reverse, extend)
- ML-KEM-768 IND-CCA2 implicit rejection
- Cross-keypair forgery (90 pair-wise checks across 10 keys)
- Entropy chi-squared test on RNG output
- Timing baseline (valid vs invalid verify within 10x)
- Pathological inputs (empty, 1B, 1MB, all-zeros, all-ones)

#### Cross-Implementation Validation
- PQClean (C via FFI) vs RustCrypto `ml-dsa` (pure Rust) — keygen, signing, cross-verify all byte-exact identical
- Both implementations match NIST ACVP expected values

#### Fuzzing
- 4 `cargo-fuzz` targets: `fuzz_mldsa_verify`, `fuzz_mldsa_sign`, `fuzz_mlkem_decap`, `fuzz_mlkem_encap`
- 41.8M executions, 0 crashes
- Seed corpus from Wycheproof vectors

#### PQC End-to-End Integration
- Block signed with ML-DSA-65 → stored in RocksDB → retrieved → signature cryptographically verified
- Tampered payload detection post-storage
- JSON wire format roundtrip preserves 3309-byte signatures
- Cross-algorithm confusion rejected (Ed25519 sig ≠ ML-DSA verifier)
- TLS PQC: ML-KEM-768 in key exchange provider, TLS 1.3 cipher suites, env toggle

#### CMVP Documentation
- `LAB_SUBMISSION_PACKAGE.md` — complete pre-assessment submission package for NVLAP lab
- `SECURITY_POLICY.md` updated with ACVP vector inventory, DRBG delegation rationale, and resolved gaps

### Changed
- `mldsa.rs`: `sign_message_raw`, `verify_signature_raw` now `pub` (was `pub(crate)`) for fuzz targets
- `mlkem.rs`: `encapsulate_raw`, `decapsulate_raw` now `pub` for fuzz targets
- `Cargo.toml`: added `cc` build-dep, `pqcrypto-internals` dep, `ml-dsa`/`serde`/`serde_json` dev-deps
- Root `Cargo.toml`: excluded `fuzz/` from workspace

### Stats
- `pqc_crypto_module`: 145 tests, 15 suites, 0 failed
- PQC E2E integration: 9 tests
- Fuzz: 4 targets, 41.8M executions, 0 crashes
- Workspace: 2688 lib tests passed, 0 failed, 3 ignored

---

## [0.11.0] — 2026-08-17

### Added — EUDI Identity Layer + real wallet interop

First credential issuance from a PQC blockchain to a real EU Digital Identity Wallet.

#### EUDI Protocol Stack (OID4VCI 1.0 Final)
- **ES256 (ECDSA P-256) signing provider** — `EcdsaP256SigningProvider` for EUDI-compatible credential signing
- **OID4VCI issuer metadata** — `/.well-known/openid-credential-issuer` with `dc+sd-jwt` format, `credential_definition`, `credential_metadata`, three credential configs (`IdentityCredential_sd_jwt`, `eudi_pid_sd_jwt`, `eudi_pid_mdoc`)
- **OAuth AS metadata** — `/.well-known/oauth-authorization-server` (RFC 8414) with PAR, DPoP, attestation signing alg support
- **JWT VC Issuer metadata** — `/.well-known/jwt-vc-issuer` serving JWKS for SD-JWT VC signature verification
- **Nonce endpoint** — `POST /nonce` with single-use enforcement via `NonceStore` (5 min TTL)
- **Token endpoint** — `POST /token` accepting pre-authorized code, `client_id`, `tx_code`, DPoP, WIA
- **Credential endpoint** — `POST /credential` issuing `dc+sd-jwt` VCs with `cnf` holder key binding, `kid` in header, `iss` as issuer URL
- **Credential offer** — `POST /credential_offer` generating `openid-credential-offer://` deep links
- **Attestation proof type** — `proofs.attestation` support with recursive `key_attestation` JWK extraction
- **OID4VP 1.0 Final** — DCQL-only (dropped PresentationDefinition), `direct_post` response mode

#### Attestation & Status
- **Attestation Status List** — IETF Token Status List (draft-20/21), `statuslist+jwt` with ZLIB compression, 2-bit entries (VALID/SUSPENDED/REVOKED), `StatusListStore` in `AppState`
- **Attestation Type Registry** — PID/EAA/QEAA/PuB-EAA hierarchy with `IssuerRole` enforcement (fail-closed)

#### Formal Verification
- **TLA+ HotStuff model** — `spec/tla/GoyaHotStuff.tla`, 300M states simulated, 0 violations
- **ChainAncestryChecker** — O(1) hash→height index for BFT ancestry checks

### Changed
- SD-JWT format: `vc+sd-jwt` → `dc+sd-jwt` (OID4VCI 1.0 Final rename, both accepted in handler)
- SD-JWT `iss` field: DID → issuer URL (wallet validates `iss == credential_issuer`)
- SD-JWT `typ` header: `dc+sd-jwt`
- SD-JWT `vct` for PID: `urn:eudi:pid:1`
- Credential response: `credential` + `credentials` array (wallet expects plural)
- OID4VCI endpoints at root path (not `/api/v1`) — wallet standard
- `/token` exempt from JSON Content-Type middleware (form-urlencoded)
- `SIGNING_ALGORITHM` accepts `ecdsa-p256` / `es256` / `p256`

### Deployment
- Live at `https://goya-node.fly.dev` with HTTPS
- Verified with EUDI Reference Wallet (iOS) — full pre-authorized code flow: metadata discovery → token → nonce → credential issuance
- SD-JWT VC stored in wallet successfully

### Stats
- 2688 tests passed, 0 failed, 3 ignored
- fmt + clippy clean

---

## [0.10.1] — 2026-08-16

### Fixed — BFT 4-node quorum + Fly networking

- **Self-vote in BFT quorum** — nodes emitted votes via broadcast but never counted themselves in the local vote collector. With quorum=3 (4 validators), each node only saw 2 remote votes and never reached quorum. Now `handle_action` feeds signed votes back into the `RoundManager` after broadcasting. Full 3-phase HotStuff (Prepare→PreCommit→Commit→Decide) proven with 4 nodes across 4 continents (IAD/CDG/NRT/SIN), identical block hash on all nodes.
- **Peer address dedup** — 6 insertion points in `network/mod.rs` now filter `0.0.0.0`, empty, and self addresses. Eliminates duplicate/unreachable peers from the broadcast list.
- **`broadcast_message` / `broadcast_ordered_block` skip self** — no longer sends BFT votes or blocks to the broadcasting node's own address.
- **TCP chunk accumulation in `send_and_wait`** — state sync responses larger than one TCP segment were truncated (`EOF while parsing`). Now accumulates chunks with deadline-based timeout until valid JSON parses.
- **Flycast DNS for Fly.io P2P** — `P2P_EXTERNAL_ADDRESS` and `BOOTSTRAP_NODES` moved from secrets to `fly.toml` env using `.flycast` DNS (direct container routing, bypasses Fly's TCP proxy that broke peer identity).

### Changed

- `handle_action` in BFT controller now takes `&mut RoundManager` to feed self-votes back into the state machine.
- `Peers` message handler filters invalid addresses before insertion.
- `process_message` Version handler applies same `0.0.0.0` filter as `handle_connection`.

---

## [0.10.0] — 2026-08-15

### Changed — Post-quantum default + server-side PDF notarization

- **ML-DSA-65 as default signing algorithm** (`src/main.rs`)
  - Node defaults to ML-DSA-65 (FIPS 204) when `SIGNING_ALGORITHM` is unset (was Ed25519)
  - Ed25519 remains available via `SIGNING_ALGORITHM=ed25519` but logs deprecation warning
  - All node signatures (TSA, OCSP, endorsement, mining, FEA) are now post-quantum
- **`/sign/fea` fix** — endpoint was using the node's generic provider (Ed25519 by default), causing FEA notarizations to be rejected by `validate_fes_fea`. Now correctly requires ML-DSA-65 with defense-in-depth guard
- **`POST /notarize/pdf` rewritten to server-side signing (Option B)**
  - Client sends only: `pdf_base64`, `signer`, `biometric_evidence`
  - Node computes dimensional fingerprint, signs canonical_hash with ML-DSA-65, produces CAdES DER envelope
  - Returns signature + public_key + fingerprint + cades_der in one roundtrip
  - PQC key never leaves the node — more secure, simpler for clients
- **Removed `fea_signing_provider`** — single ML-DSA-65 provider for all endpoints, no dual-key confusion

### Fixed

- `/sign/fea` returning Ed25519 keys instead of ML-DSA-65, causing `validate_fes_fea` to reject the node's own signature

### Infrastructure

- Deployed 4-node BFT testnet: Fly.io (Virginia, Singapore), AWS (Ireland), Oracle Cloud (Valparaíso ARM)
- Added `fly.node2.toml` (CDG) and `fly.node3.toml` (NRT) configs

### Stats

- Suite total: 2539 passed, 0 failed, 3 ignored
- FES and FEA both use ML-DSA-65 — algorithm difference eliminated, only biometric requirement distinguishes them

---

## [0.9.2] — 2026-08-14

### Added — Certification readiness + EUDI Wallet interop simulation

- **Extended QCStatements** (`src/pki.rs`) — EN 319 412-5
  - `QcStatementsParams` struct with `qscd`, `retention_years`, `limit_value_cents`
  - `build_qc_statements_der_ext()` — generates QcSSCD (0.4.0.1862.1.4), QcRetentionPeriod (0.4.0.1862.1.3), QcLimitValue (0.4.0.1862.1.2)
  - `QC_SSCD_OID`, `QC_RETENTION_OID`, `QC_LIMIT_VALUE_OID` constants
  - Backwards-compatible: `build_qc_statements_der()` delegates to ext with defaults
- **Full subject DN for qualified certificates** (`src/pki.rs`) — EN 319 412-2/3
  - `SubjectIdentity` struct: `given_name`, `surname`, `serial_number`, `country`, `organization`, `organization_id`
  - `sign_node_cert_with_subject()` — issues certs with complete DN (givenName 2.5.4.42, surname 2.5.4.4, serialNumber 2.5.4.5, organizationIdentifier 2.5.4.97)
  - `sign_node_cert()` unchanged (backwards-compatible, delegates with default identity)
- **eIDAS Level of Assurance** (`src/identity/ra.rs`) — Regulation 2015/1502
  - `EidasLoA` enum: `Low`, `Substantial`, `High`
  - `loa_from_method()` — derives LoA from proofing method (InPerson→High, Video/UaePass→Substantial, Remote→Low)
  - `IdentityProofing.loa` field (serde default, backwards-compatible)
- **Certification readiness test suite** (`tests/certification_readiness.rs`) — 18 tests
  - QCStatements: basic, QSCD, retention, limit value, profile differentiation
  - Certificate DN: natural person (Arabic name + Emirates ID), legal person (org + VAT), backwards compat
  - LoA eIDAS: all 4 proofing methods mapped correctly
  - Multi-jurisdiction: RUT, Emirates ID, EU national ID validation
  - SD-JWT VC structure validation with Arabic claims
  - mdoc full verification flow (issuer auth + device auth)
- **EUDI Wallet interop test suite** (`tests/eudi_wallet_interop.rs`) — 7 tests
  - SD-JWT VC: issue PID → selective disclosure → verify (EUDI PID flow)
  - SD-JWT VC: zero-disclosure presentation
  - mdoc: issue → DeviceResponse with DeviceAuth → issuer verify + device verify
  - PKCE S256 RFC 7636 roundtrip
  - Cross-jurisdiction: EmiratesIDCredential (Arabic), ChileanPIDCredential
  - DeviceResponse JSON wire format serialization roundtrip

### Stats

- 25 new integration tests + lib suite 2534 passed, 0 failed
- 3 high-severity certification gaps closed (QCStatements, DN, LoA)
- 2 simulation test suites validate certification + wallet interop readiness

---

## [0.9.1] — 2026-08-14

### Added — EU/UAE digital identity critical gaps closed (5 of 5)

- **mdoc Device Authentication** (`src/identity/mdoc.rs`) — ISO 18013-5 §9.1.3
  - `DeviceAuth` struct — COSE_Sign1 proof of device key possession
  - `sign_device_auth()` / `verify_device_auth()` — holder proves control of device_key in MSO
  - `DeviceResponse` + `Document` structs — ISO 18013-5 §8.3 response format
  - 3 tests (sign+verify, wrong key, session binding)
- **mdoc Session Transcript** (`src/identity/mdoc.rs`) — ISO 18013-5 §9.1.5
  - `SessionTranscript` struct — device_engagement + reader_key + handover
  - `compute_session_transcript_hash()` — SHA-256 of CBOR-encoded transcript
  - 2 tests (deterministic hash, roundtrip)
- **OpenID4VCI authorization_code grant** (`src/api/handlers/oid4vci.rs`) — OpenID4VCI §3.4
  - Token endpoint accepts both `pre-authorized_code` and `authorization_code` grant types
  - `verify_pkce()` — PKCE S256 challenge verification (RFC 7636)
  - `CredentialOffer` struct + `POST /credential_offer` endpoint (OpenID4VCI §4.1)
  - Generates `openid-credential-offer://` URI with pre-authorized code
  - 6 tests (auth_code flow, missing code, PKCE valid/invalid, credential offer, metadata grants)
- **OpenID4VP DCQL** (`src/api/handlers/oid4vp.rs`) — OpenID4VP draft-24 §5.3
  - `DcqlQuery`, `CredentialQuery`, `ClaimQuery` structs
  - `match_dcql_query()` — validates format + required claims against disclosed data
  - `create_request` accepts either `presentation_definition` or `dcql_query`; rejects neither
  - `submit_response` dispatches to DCQL or PresentationDefinition matching
  - 3 tests (valid, missing claim, format mismatch) + 1 E2E (create with DCQL) + 1 E2E (rejects neither)
- **OpenID4VP response_mode + client_id_scheme** (`src/api/handlers/oid4vp.rs`) — OpenID4VP §7.3
  - `AuthorizationRequest` now carries `response_mode` (default `direct_post`) and `client_id_scheme`
  - Supports `direct_post.jwt` response mode declaration
  - 1 E2E test (create request with response_mode + client_id_scheme)

### Changed

- `issuer_metadata`: `credentials_supported` (array) → `credential_configurations_supported` (object, draft-13+)
- `issuer_metadata`: added `grant_types_supported` and `credential_offer_endpoint`
- `issuer_metadata`: added `emirates_id` claim to SD-JWT configuration
- `AuthorizationRequest.presentation_definition` → `Option<PresentationDefinition>` (DCQL alternative)
- Token endpoint `unsupported_grant_type` message now lists both supported types

### Stats

- 16 new tests — suite total: 2534 passed, 0 failed, 3 ignored
- 5 critical EU/UAE identity gaps closed (mdoc device auth, session transcript, authorization_code, DCQL, direct_post.jwt)

---

## [0.9.0] — 2026-08-14

### Added — UAE regulatory compatibility (Federal Decree-Law 46/2021)

- **Emirates ID validation** (`src/identity/ra.rs`)
  - `validate_emirates_id()` — format 784-YYYY-NNNNNNN-C with Luhn check digit
  - Accepts hyphenated, spaced, and raw digit formats; returns normalized form
  - 6 tests (valid formats, wrong country code, wrong length, bad check digit, implausible year)
- **Multi-jurisdiction Registration Authority**
  - `Jurisdiction` enum: `Chile`, `Uae`, `Eu` (default `Chile`, backwards-compatible via `#[serde(default)]`)
  - `validate_national_id()` — dispatches validation by jurisdiction (RUT, Emirates ID, EU national ID)
  - `ProofingMethod::UaePass` — UAE Pass digital identity verification method
  - `IdentityProofing` struct: `national_id` and `jurisdiction` fields (serde defaults preserve legacy JSON)
  - 7 tests (dispatch per jurisdiction, serde roundtrip, backwards compat)
- **UAE audit retention** (`src/audit_retention.rs`)
  - `UAE_RETENTION_SECS` constant — 15 years per DL 46/2021 Art. 10 (was only 7-year Chilean default)
- **UAE compliance documentation** (`docs/compliance/UAE-COMPLIANCE.md`)
  - DL 46/2021 article-by-article mapping (Art. 1, 10, 11, 19, 20, 21)
  - Cabinet Resolution 28/2023 (TDRA executive regulation)
  - TDRA Trust Service Provider requirements mapped to GOYA modules
  - Emirates ID / UAE Pass integration architecture
  - PDPL (DL 45/2021) data protection assessment
  - VARA (Dubai), ADGM (Abu Dhabi), SCA/CBUAE regulatory landscape
  - 4-jurisdiction comparison table (Chile/EU/UAE/US)
  - Gap analysis with severity and remediation path

### Changed

- `ELECTRONIC-SIGNATURE-COMPLIANCE.md` updated: 4 jurisdictions (was 3), UAE items in roadmap, TSA/CAdES/XAdES/PAdES marked as Done (were Planned)

### Stats

- 221 lines added across 3 modified files + 1 new file
- Suite total: 2518 passed, 0 failed, 3 ignored
- GOYA now covers Chile (Ley 19.799) / EU (eIDAS) / US (ESIGN) / UAE (DL 46/2021)

---

## [0.8.0] — 2026-08-13

### Fixed — Security hardening (9 fixes)

- **KB-JWT signature verification** — `verify_kb_jwt()` now verifies cryptographic signature + jkt thumbprint match (was accepting any JWT without verification)
- **SD-JWT `exp` validation** — `verify_sd_jwt_vc()` rejects expired credentials (was ignoring exp claim entirely)
- **Token endpoint code entropy** — enforces minimum 16-char pre-authorized code (was accepting 1-char codes)
- **DPoP JWT signature verification** — verifies signature using JWK embedded in header via `extract_pubkey_from_jwk()` (was structural-only)
- **WIA JWT signature verification** — `verify_wia()` verifies signature via `WalletProviderRegistry` issuer key lookup (was structural-only)
- **mdoc COSE RSA algorithm ID** — corrected to `-37` (IANA PS256), was placeholder `-257`
- **Audit purge hash chain integrity** — `MemoryAuditStore::purge_expired()` re-seals hash chain after entry removal (was breaking chain)
- **VP nonce replay protection** — `verify_sd_jwt_presentation()` checks JWT/KB-JWT nonce against authorization request (was hardcoded `true`)
- **proof_jwt iat freshness** — `verify_proof_jwt()` enforces 5-minute window (was accepting arbitrarily old proofs)
- **Notarize handler panic** — `read_notarization_by_hash().unwrap()` replaced with proper `Err→404` response
- **Rate limiter panic** — `get_mut().unwrap()` replaced with `entry()` return value

### Added

- **`WalletProviderRegistry`** — in-memory issuer→pubkey store for WIA signature verification
- **`verify_sd_jwt_vc_with_holder()`** — full KB-JWT cryptographic verification with holder public key
- **`extract_pubkey_from_jwk()`** — JWK→raw pubkey extraction for Ed25519/RSA
- **CRL endpoint per-MSP** — `GET /api/v1/crl/{msp_id}` and `/crl/{msp_id}/pem` (was hardcoded "default")

### Added — Regulatory policy documentation (14 documents)

- `docs/policy/CPS.md` — Certification Practice Statement (RFC 3647, 75 KB)
- `docs/policy/CP.md` — Certificate Policy (RFC 3647, 61 KB)
- `docs/policy/ETSI-EN-319-401-TSP-POLICY.md` — General TSP policy requirements (46 KB)
- `docs/policy/ETSI-EN-319-411-CA-POLICY.md` — CA policy for qualified certificates (33 KB)
- `docs/policy/ETSI-EN-319-421-TSA-POLICY.md` — TSA policy and security requirements (29 KB)
- `docs/policy/PLAN-SEGURIDAD.md` — Security plan per DS 181 (Spanish, 30 KB)
- `docs/policy/PLAN-CONTINGENCIA.md` — Business continuity plan per DS 181 (Spanish, 30 KB)
- `docs/policy/PROCEDIMIENTO-CEREMONIA-CLAVES.md` — Key ceremony procedure (Spanish, 64 KB)
- `docs/policy/POLITICA-PRIVACIDAD-EIPD.md` — Privacy policy + DPIA (Ley 19.628/GDPR, Spanish, 30 KB)
- `docs/policy/ACUERDO-SUSCRIPTOR.md` — Subscriber agreement (Spanish, 35 KB)
- `docs/policy/ACUERDO-PARTE-CONFIANTE.md` — Relying party agreement (Spanish, 30 KB)
- `docs/policy/INFORME-INTEROPERABILIDAD.md` — Interoperability test report template (Spanish, 25 KB)
- `docs/policy/OID-REGISTRY.md` — OID namespace registry + IANA PEN instructions
- `docs/policy/CHECKLIST-PRE-CERTIFICACION.md` — 48-item pre-certification checklist

### Stats

- Suite total: 2509 passed, 0 failed, 3 ignored
- 14 policy documents, ~500 KB total
- 0 `unwrap()` on external input paths (was 2)
- All cryptographic verification paths validated (KB-JWT, DPoP, WIA, VP nonce, proof iat, SD-JWT exp)

---

## [0.7.1] — 2026-08-13

### Added — Production operational improvements

- **RocksDB audit `purge_expired()`** (`src/storage/adapters.rs`)
  - Iterates `audit_log` CF, parses entry JSON for timestamp, deletes purgeable keys
  - Respects `auto_purge_enabled` and `max_retention_secs` policy flags
  - 2 tests (purge + disabled noop)
- **CRL Distribution Point** (`src/api/handlers/crl.rs`) — new file
  - `GET /api/v1/crl` — serves DER-encoded RFC 5280 CRL (`application/pkix-crl`)
  - `GET /api/v1/crl/pem` — serves PEM-encoded CRL (`application/x-pem-file`)
  - Generates CRL on-the-fly from `CrlStore` + `NodeCaConfig`
  - 2 tests (503 without store, 503 without CA)
- **PAdES CMS PKCS#7** (`src/signature/pades.rs`)
  - `build_pades_cms()` — CMS detached signature for PDF byte range via CAdES-BES DER
  - `verify_pades_cms()` — verifies CMS against original PDF byte range
  - x509-parser interop: id-signedData OID verified
  - 3 tests (roundtrip, wrong key, interop)
- **CAdES-XL long-term validation** (`src/signature/cades_der.rs`)
  - `build_cades_xl_der()` — embeds certificate chain + CRL in unsigned attributes (ETSI TS 101 733 §6.3)
  - `CadesXlParams` — input struct for cert chain + CRL DER bytes
  - OIDs: `id-aa-ets-certValues` (1.2.840.113549.1.9.16.2.23), `id-aa-ets-revocationValues` (1.2.840.113549.1.9.16.2.24)
  - Preserves original CAdES-T signature (verify roundtrip confirmed)
  - 3 tests (embed, verify preservation, x509-parser interop)

### Changed

- `api/handlers.rs`: added `crl` module
- `api/routes.rs`: registered CRL endpoints under OCSP section

### Stats

- 349 lines added across 5 modified files + 1 new file
- Suite total: 2503 passed, 0 failed, 3 ignored

---

## [0.7.0] — 2026-08-13

### Added — 10 final compliance gaps closed

- **F3: OCSP DER encoding** (`src/msp/ocsp_der.rs`)
  - RFC 6960 binary OCSPResponse: BasicOCSPResponse with BIT STRING signature, CertID, CertStatus (good/revoked/unknown), nonce extension
  - `encode_ocsp_response_der()` + `verify_ocsp_response_der()` roundtrip
  - `POST /api/v1/ocsp/query/der` — returns `application/ocsp-response`
  - x509-parser interop test
  - Ed25519 + ML-DSA-65 support, 11 tests
- **F4: OpenID4VCI DPoP + WIA + c_nonce** (`src/api/handlers/oid4vci.rs`)
  - DPoP proof validation (RFC 9449): typ, htm, htu, iat freshness, jti, JWK thumbprint binding
  - Token endpoint returns `token_type: "DPoP"` + `dpop_jkt` when DPoP header present
  - Wallet Instance Attestation (WIA) validation: typ, iss, sub, exp
  - `verify_proof_jwt()` — c_nonce binding on credential endpoint (OpenID4VCI §7.2.1)
  - Credential endpoint accepts both `Bearer` and `DPoP` authorization
  - 20 tests
- **F5: OpenID4VP presentation_definition matching** (`src/api/handlers/oid4vp.rs`)
  - `match_presentation_definition()` — format compatibility, required field constraints, nested namespace support
  - Issuer key registry on `VpRequestStore` — `register_issuer_key()` / `resolve_issuer_key()`
  - SD-JWT signature verification via issuer key lookup; `valid: false` when key unknown
  - Disclosed claims extraction from SD-JWT disclosures
  - 6 tests
- **F6: SD-JWT Key Binding JWT** (`src/identity/sd_jwt.rs`)
  - `jwk_thumbprint()` — RFC 7638 JWK thumbprint for Ed25519/ML-DSA-65/RSA
  - `issue_sd_jwt_vc_with_kb()` — SD-JWT with `cnf.jkt` holder key binding
  - `present_sd_jwt_with_kb()` — presentation with KB-JWT (typ `kb+jwt`, `sd_hash`, `aud`, `nonce`)
  - `verify_sd_jwt_vc()` updated — detects and verifies KB-JWT, sets `kb_verified`
  - 5 tests
- **F7: XAdES sign real SignedInfo** (`src/signature/xades.rs`)
  - `to_xades_bes_signed()` — W3C XML Signature §3.1.2: SignatureValue over actual `<ds:SignedInfo>` XML
  - `verify_xades_signature()` — extracts SignedInfo, verifies against embedded public key
  - Ed25519, ML-DSA-65, RSA support
  - 7 tests (roundtrip, tamper, wrong key, all algorithms)
- **F8: ETSI TL signature verification** (`src/tsl_client.rs`)
  - `verify_tl_signature()` — extracts `<ds:Signature>` from TL XML, verifies via XAdES
  - `TlSignatureResult` — signed, signature_valid, signer_algorithm, signing_time
  - 4 tests
- **F9: QCStatements X.509 extension** (`src/pki.rs`)
  - `build_qc_statements_der()` — EN 319 412-5: QcCompliance + QcType (esign/eseal/web)
  - `qc_statements_extension()` — OID 1.3.6.1.5.5.7.1.3 CustomExtension for rcgen
  - 6 tests (3 profiles, differentiation, extension build, cert issuance)
- **F10: DID consolidation** — 142 occurrences across 19+ files
  - `did:bc:` → `did:goya:`, `did:example:` → `did:goya:`, `did:key:` → `did_from_pubkey_hex()`
  - `DidDocument::create_did()`, `parse()`, `from_public_key()` all use `did:goya:` prefix
  - Zero non-`did:goya:` DID formats remain
- **F11: Audit retention auto-purge** (`src/audit.rs`)
  - `AuditStore::purge_expired()` — removes entries older than `max_retention_secs`
  - `MemoryAuditStore` implementation via `Vec::retain`
  - `spawn_auto_purge_task()` — tokio background task with configurable interval + AtomicBool shutdown
  - 4 tests (purge, disabled noop, max_zero noop, async integration)
- **F12: TSA serial persistence** (`src/tsa/mod.rs`)
  - `with_serial_path()` — loads last serial from disk, takes `max(saved, epoch_seed)`
  - `next_serial()` — atomic increment + persist to disk after each issuance
  - Restart-safe: serial never goes backwards
  - 4 tests (persist, reload, restart simulation, missing file fallback)

### Changed

- `OcspResponse` handler: `signing_provider` wired for DER encoding
- `TokenRequest`: added `wallet_instance_attestation` field
- `TokenResponse`: added `dpop_jkt` field, `token_type` switches to `"DPoP"`
- `VpRequestStore`: added `issuer_keys` registry field
- `VerifiedSdJwt`: added `kb_verified` field
- `TsaProvider`: added `serial_path` field, `next_serial()` replaces raw `fetch_add`
- `SigningProvider` import added to `xades.rs`
- OCSP route registration includes `/ocsp/query/der`

### Stats

- 2184 lines added, 202 removed across 34 modified files + 1 new file
- Suite total: 2493 passed, 0 failed, 3 ignored
- All 10 compliance gaps closed (F3–F12)

---

## [0.6.1] — 2026-08-13

### Added — Cert chain validation + RA-to-PKI bridge

- **X.509 certificate chain validator** (`src/pki_chain.rs`)
  - `validate_chain()` — PEM chain parsing, validity period check, issuer→subject linking, CA basic constraints, trust store verification
  - `validate_cert_der()` — single DER certificate validity check
  - Supports 2-level (root+leaf) and 3-level (root+intermediate+leaf) hierarchies
  - Extracts owned `CertInfo` structs (no lifetime issues with x509-parser)
  - 7 tests (valid chain, expired, empty, self-signed, DER valid/expired, 3-level hierarchy)
- **RA approve → certificate issuance** (`src/identity/ra.rs`)
  - `RaStore::approve_and_issue_cert()` — approves identity proofing AND issues X.509 cert signed by CA in one atomic operation
  - Connects RA identity verification to PKI certificate generation (`sign_node_cert`)
  - 2 tests (success path with PEM output, failure without proofing)

### Stats

- 49 lines added across 3 modified files + 1 new file
- Suite total: 2426 passed, 0 failed, 3 ignored

---

## [0.6.0] — 2026-08-13

### Added — EU digital identity / eIDAS 2.0 interoperability

- **SD-JWT VC** (`src/identity/sd_jwt.rs`) — RFC 9901
  - `issue_sd_jwt_vc()` creates selectively disclosable JWT credentials
  - `present_sd_jwt()` builds presentations with chosen disclosures only
  - `verify_sd_jwt_vc()` verifies signature + disclosure hash binding
  - Supports Ed25519 (`EdDSA`), ML-DSA-65, RSA (`RS256`)
  - JWT type `vc+sd-jwt`, `_sd_alg: sha-256`, `vct` claim per draft-ietf-oauth-sd-jwt-vc
  - 11 tests (full roundtrip, selective disclosure, tamper detection, all algorithms)
- **mdoc ISO/IEC 18013-5** (`src/identity/mdoc.rs`)
  - CBOR-encoded credentials via `ciborium`
  - `MobileSecurityObject` with per-element SHA-256 digests
  - COSE_Sign1 issuer authentication
  - Namespace-based selective disclosure via `present_mdoc()`
  - `verify_mdoc()` checks signature + element digest integrity
  - 9 tests (issuance, selective disclosure, tamper, multi-namespace, CBOR roundtrip)
- **OpenID4VCI** (`src/api/handlers/oid4vci.rs`) — credential issuance
  - `GET /.well-known/openid-credential-issuer` — issuer metadata (SD-JWT + mdoc)
  - `POST /token` — pre-authorized code flow token exchange
  - `POST /credential` — issue SD-JWT VC or mdoc based on `format` parameter
  - 7 E2E tests (metadata, token, SD-JWT issuance, mdoc issuance, error paths)
- **OpenID4VP** (`src/api/handlers/oid4vp.rs`) — credential presentation
  - `POST /api/v1/oid4vp/request` — create presentation request with `PresentationDefinition`
  - `GET /api/v1/oid4vp/request/{id}` — cross-device request retrieval
  - `POST /api/v1/oid4vp/response` — submit `vp_token` (SD-JWT or mdoc)
  - `VpRequestStore` for cross-device QR code flow
  - 5 E2E tests (create+fetch, SD-JWT response, mdoc response, error paths)
- **ETSI TS 119 612 Trusted List client** (`src/tsl_client.rs`)
  - Parse LOTL (List of Trusted Lists) and country-level TLs from XML
  - `is_qualified_tsp()` checks QTSP status by service type
  - `find_qualified_services()` enumerates qualified services
  - ETSI service status/type URI constants
  - 8 tests (country TL, LOTL pointers, qualified check, withdrawn detection)
- **ETSI TS 119 612 Trusted List publisher** (`src/tsl.rs`)
  - `TrustServiceList::to_xml()` generates ETSI-compliant XML
  - Maps `ServiceType` and `ServiceStatus` to ETSI URIs
  - Roundtrip test: `to_xml()` → `tsl_client::parse_trusted_list()` → verify
  - 3 XML tests
- **ETSI EN 319 412 certificate profile OIDs** (`src/pki_policy.rs`)
  - QCStatements: `QC_COMPLIANCE_OID`, `QC_TYPE_OID`
  - QC types: `QCT_ESIGN_OID` (natural person), `QCT_ESEAL_OID` (legal person), `QCT_WEB_OID`
  - `CertProfileType` enum: `NaturalPerson`, `LegalPerson`, `WebAuthentication`
- **Qualified Seal** (`src/signature/mod.rs`)
  - `SignatureLevel::Seal` for legal entity signatures (eIDAS Art. 3(25))
  - Requires ML-DSA-65, biometric binding same as FEA
  - All `match` arms updated across cades, xades, notarize handlers
- **eIDAS level on credentials** (`src/storage/traits.rs`)
  - `Credential::eidas_level()` and `set_eidas_level()` via claims field
  - Values: `none`, `low`, `substantial`, `high`
  - No breaking schema change — stored in existing `claims` JSON

### Changed

- `ciborium = "0.2"` added as direct dependency (was transitive via criterion)
- `SignatureLevel` enum: added `Seal` variant; all exhaustive matches updated
- `notarize.rs`: `Seal` treated same as `Advanced` for payload construction
- OID4VCI/VP routes registered in `ApiRoutes::configure()`

### Stats

- 190 lines added across 14 modified files + 5 new files
- Suite total: 2417 passed, 0 failed, 3 ignored
- 10 EU interoperability items addressed (9 implemented, 1 documented as tech debt)

---

## [0.5.0] — 2026-08-13

### Added — FEA certification readiness (24 gaps closed)

- **RFC 3161 DER TimeStampResp** (`src/tsa/rfc3161_der.rs`)
  - DER-encoded TSTInfo per RFC 3161 §2.4.2 with CMS SignedData wrapper
  - Build + verify roundtrip for Ed25519, ML-DSA-65, RSA
  - API endpoint: `POST /api/v1/tsa/timestamp/der` (content-type `application/timestamp-reply`)
  - 16 tests + 3 x509-parser interop tests
- **TimeSource integration in TSA**
  - `TsaProvider.with_time_source()` accepts pluggable `dyn TimeSource`
  - NTP enforcement: TSA rejects if `time_source.validate()` fails
  - TSA validates own signer health before issuing
  - Serial numbers seeded from epoch to avoid cross-restart collisions
- **CAdES-T timestamp embedding** (`src/signature/cades_der.rs`)
  - `build_cades_t_der()` adds `id-smime-aa-timeStampToken` (1.2.840.113549.1.9.16.2.14) as unsigned attribute
  - `verify_cades_bes_der()` extracts timestamp token from unsigned attrs
  - 5 CAdES-T tests
- **ETSI TS 101 733 signed attributes** (`src/signature/cades_der.rs`)
  - `id-aa-signingCertificateV2` (RFC 5035): ESSCertIDv2 with SHA-256 cert hash
  - `id-smime-aa-ets-commitmentType`: `CadesCommitment::Fes` (proofOfOrigin) / `Fea` (proofOfApproval)
  - `id-smime-aa-ets-sigPolicyId`: Decreto 24 signature policy OID + hash
  - Certificate embedding in CMS `certificates [0] IMPLICIT`
  - `CadesParams` struct for full control; `build_cades_der()` public API
  - 6 ETSI compliance tests
- **Certificate chain verification** (`src/signature/cades_der.rs`)
  - `VerifyContext` with trusted roots, CRL store, timestamp verification flag
  - `verify_cades_with_context()` validates cert hash, checks CRL revocation, verifies timestamp token structure
  - 3 context verification tests
- **PKCS#11 HsmSigningProvider** (`src/identity/hsm.rs`)
  - Real PKCS#11 session: slot discovery, `CKA_LABEL` key lookup, `CKA_EC_POINT` public key extraction
  - `CKM_EDDSA` signing and verification via cryptoki 0.7
  - `backup_info()` documents key backup requirements
  - Feature-gated under `hsm = ["cryptoki"]`
- **CPS/CP markdown export** (`src/pki_policy.rs`)
  - `CertificatePolicy::to_markdown()` and `CertificationPracticeStatement::to_markdown()` — RFC 3647 section structure
  - API endpoints: `GET /api/v1/cps/document`, `GET /api/v1/cp/document` (content-type `text/markdown`)
  - 8 tests (section presence, table rendering, compliance refs)
- **CAVP NIST test vectors**
  - SHA-256: FIPS 180-4 §B.1/B.2/B.3 (empty, abc, 448-bit, 896-bit)
  - SHA3-256: FIPS 202 (empty, abc)
  - Ed25519: RFC 8032 §7.1 test vectors 1-3 + wrong-message rejection
  - 10 CAVP tests
- **Audit log JSON export** (`src/audit.rs`)
  - `export_json()` with hash chain metadata, chain validity flag, entry count
  - `retention_status()` connected to `AuditRetentionPolicy`
  - CSV export fixed: includes metadata, previous_hash, entry_hash (was missing)
  - 7 export tests
- **Interoperability tests**
  - x509-parser: CAdES DER ContentInfo/SignedData/OID parsing (Ed25519, ML-DSA-65, RSA)
  - x509-parser: RFC 3161 TimeStampResp structure (PKIStatus, id-ct-TSTInfo OID)
  - OpenSSL CLI: `asn1parse` validates RSA CAdES, Ed25519 CAdES, CAdES-T DER
  - 10 interop tests
- **XAdES-T** (`src/signature/xades.rs`)
  - `to_xades_t()` embeds timestamp token in `UnsignedProperties/SignatureTimeStamp`
  - Fixed `unwrap_or_default()` in hex_to_base64 (returns empty on invalid hex)
  - 3 XAdES-T tests
- **OCSP improvements** (`src/msp/ocsp.rs`)
  - `verify_nonce()` properly distinguishes `None` from `Some(0)`
  - `OcspResponse::to_export_json()` with verification flag
  - Nonce payload uses `"none"` string for absent nonce (not `"0"`)
  - 3 OCSP tests
- **FEA endpoint rewrite** (`src/api/handlers/notarize.rs`)
  - Uses node's persistent signing provider (not ephemeral throwaway keys)
  - Produces CAdES DER with FEA commitment + policy OID
  - Biometric hash included in signing content
  - Format parameter (`json`, `cades-der`, `cades-t`) in `SignFeaRequest`
  - Emits `CertificateIssued` audit event
- **PSC certification roadmap** (`docs/compliance/PSC-CERTIFICATION-ROADMAP.md`)
  - 4-phase plan: Legal → HSM+DC → Consultor → Auditoría
  - Timeline: 6-8 months, USD 47-89K estimated
- **SoftHSM2 integration test** (`tests/softhsm_pkcs11.rs`)
  - Feature-gated `#[cfg(feature = "hsm")]`, skips gracefully without SoftHSM2

### Changed

- `TsaProvider`: time source pluggable, NTP validation mandatory, signer self-check before issuing
- `sign_fea` endpoint: persistent provider, CAdES DER output, audit emission
- `MemoryCrlStore`: `Mutex` → `RwLock` for concurrent read performance
- `renew_node_cert`: removed `#[allow(dead_code)]`, documented revocation requirement
- `VerifyContext` added to CAdES DER verification path
- RA store, OCSP responder, LifecycleManager initialized in `main.rs` (were `None`)
- Light client: documented FEA dependency on full node

### Stats

- 2014 lines added, 112 removed across 19 files
- Suite total: 2374 passed, 0 failed, 3 ignored
- 24 FEA certification gaps closed (8 blocker, 5 high, 11 medium/low)

---

## [0.4.0] — 2026-08-05

### Added — Regulatory gaps closed

- **ASN.1/DER native CAdES/PAdES** (`src/signature/cades_der.rs`, `pades_der.rs`)
  - Standards-compliant CMS SignedData (RFC 5652) DER binary output
  - Signature covers DER-encoded SignedAttributes per §5.4
  - Zero new ASN.1 deps — pre-computed OIDs, inline DER encoder/parser
  - Build + verify roundtrip with Ed25519, ML-DSA-65, and RSA
  - PAdES reuses CAdES CMS blob (PDF embedding is frontend concern)
  - 12 tests
- **RSA SigningProvider** (`rsa` crate 0.9)
  - `SigningAlgorithm::Rsa` variant — RSA-2048 PKCS#1 v1.5 SHA-256
  - `RsaSigningProvider` implementing `SigningProvider` trait
  - `verify_rsa()` in verify dispatcher, all match arms updated
  - RSA KAT added to FIPS 140-3 self-tests
  - XAdES/CAdES/PAdES OIDs for sha256WithRSAEncryption
  - 10 tests
- **ISO 19794-2 fingerprint minutiae template parsing** (`src/signature/iso19794.rs`)
  - `parse_fingerprint_template()` validates magic, version, record length, minutiae structure
  - `validate_fingerprint_template()` for pre-commitment validation
  - `BiometricEvidence::validate_with_template()` binds raw template to commitment hash
  - 18 tests
- **Crypto boundary allowlist** updated for RSA signing files

### Changed

- `SigningAlgorithm` enum: added `Rsa` variant (Ed25519, MlDsa65, Rsa)
- `sha2` dependency: added `oid` feature for RSA PKCS#1v1.5 compatibility
- Algorithms section: Ed25519, ML-DSA-65, **RSA-2048**, ML-KEM-768, SHA-256, SHA3-256

### Stats

- 36 new tests — suite total: 4928 passed, 0 failed
- 3 regulatory gaps moved from "partial" to "implemented"

## [Unreleased]

### Added

- **NTP system hook** (`src/time_source.rs`)
  - `parse_chronyc_output()` and `parse_timedatectl_output()` parse real NTP daemon output
  - `check_ntp_sync()` runs chronyc/timedatectl and feeds `NtpTimeSource::set_sync_status()`
  - 7 tests (chronyc synced/not-synced/empty, timedatectl variants, live check)
- **Certificate lifecycle manager** (`src/pki_lifecycle.rs`)
  - `LifecycleManager` orchestrates revoke→CRL, suspend→CRL, reinstate→CRL, expiry monitoring
  - Monotonic CRL numbers, automatic event recording for audit trail integration
  - `check_expiring()` scans certificates within configurable warning window
  - 11 tests (revoke+publish, suspend+publish, reinstate, CRL numbers, expiry detection, accumulation)
- **certificatePolicies X.509 extension** (`src/pki.rs`)
  - All issued certificates (CA, intermediate, node) now carry OID 2.5.29.32 with CPS URI
  - `certificate_policies_extension()` builds DER-encoded PolicyInformation with CPS qualifier
  - Manual DER encoding (OID, IA5String, SEQUENCE) — no new dependencies
  - 4 tests (cert DER contains OID + URI, CA cert, intermediate cert)
- **Certificate suspension and renewal** (`src/msp/mod.rs`, `src/pki.rs`)
  - `Msp::suspend()` / `reinstate()` / `is_suspended()` for certificateHold (RFC 5280)
  - `validate_identity()` now rejects suspended keys
  - `renew_node_cert()` re-issues with same identity, fresh key pair
  - Revoke automatically clears suspension
  - 5 tests (suspend/reinstate lifecycle, revoked guards, revoke clears suspension, renewal key difference)
- **Compliance documentation** (`docs/compliance/`)
  - `INCIDENT-RESPONSE-PLAN.md` — P1–P4 severity classification, response team, containment procedures for CA key compromise/TSA outage/audit tampering, communication plan, testing schedule
  - `BUSINESS-CONTINUITY-DR.md` — RTO/RPO per service (OCSP 15min, CRL 1hr, TSA 4hr, CA 24hr), disaster scenarios (node failure, datacenter outage, key compromise, ransomware), backup strategy, recovery verification checklist
  - `PHYSICAL-SECURITY.md` — 3-tier facility classification (high security/operational/support), HSM physical requirements, key ceremony room specs, visitor policy, monitoring and alarms
  - `CROSS-CERTIFICATION.md` — bilateral/bridge/trust-list models, target partners (Chilean PSC, Argentina mutual recognition, government integration), algorithm interoperability matrix, establishment and termination procedures
- **Audit log retention enforcement** (`src/audit_retention.rs`)
  - `AuditRetentionPolicy` with configurable min/max retention (default 7 years per Chilean regulation)
  - `is_retained()`, `is_purgeable()`, `filter_retained()`, `count_purgeable()` for lifecycle management
  - 12 tests (defaults, boundary, filtering, purge counting, serialization)
- **Trust Service List (TSL) — ETSI TS 119 612** (`src/tsl.rs`, `src/api/handlers/tsl.rs`)
  - `TrustServiceList` with 5 service entries: CA, TSA, OCSP, RA, Electronic Signature
  - Each service includes type, status, policy OID, algorithms, formats, endpoint
  - API endpoint: `GET /api/v1/tsl`
  - 15 unit tests + 1 E2E endpoint test
- **ETSI audit event categories** (`src/audit.rs`)
  - 24 new `AuditAction` variants covering ETSI TS 102 042 requirements: key lifecycle (Generated/Activated/Deactivated/Destroyed/BackedUp/Restored), certificate lifecycle (Issued/Renewed/Suspended/Revoked), revocation services (CrlPublished/OcspResponseGenerated), TSA operations (TimestampIssued/TsaKeyRollover), RA actions (IdentityProofingSubmitted/Approved/Rejected), security officer actions (Login/ConfigChange/RoleAssigned), system events (Startup/Shutdown/AuditLogVerified)
  - All variants queryable, serializable, and integrated with tamper-evident hash chain
  - 10 tests (display, queryability, hash chain integration, serialization roundtrip)
- **CAdES-BES electronic signatures** — ETSI TS 101 733 (`src/signature/cades.rs`)
  - `CadesEnvelope` with CMS SignedData structure, SignerInfo, signed attributes (content type, message digest, signing time, signing certificate v2, commitment type FES/FEA/FEQ)
  - `extract_cades_fields()` for verification
  - 12 tests (structure, OIDs, attributes, commitment types, determinism, serialization)
- **PAdES-BES electronic signatures** — ETSI TS 102 778 (`src/signature/pades.rs`)
  - `PadesSignature` with PDF signature dictionary fields (filter, sub-filter, name, location, reason, contact, document digest, certificate digest, signature level)
  - `PadesOptions` for location/reason/contact metadata
  - `extract_pades_fields()` for verification
  - 15 tests (filter, sub-filter, options, levels, none-skipping in JSON, determinism, serialization)
- **Key Ceremony framework** (`src/pki_ceremony.rs`)
  - `KeyCeremony` builder with formal steps: EnvironmentCheck, KeyGeneration, WitnessAttestation, KeySplit, ShareDistribution, KeyVerification, Activation
  - `CeremonyConfig` with M-of-N threshold, notary requirement, minimum witnesses
  - `CeremonyRecord` with SHA-256 tamper-evident hash, `verify_record()` for integrity
  - Validation enforces required participants (custodians, witnesses, notary) and steps before finalization
  - Abort flow with reason recording
  - 17 tests (full ceremony, validation failures, abort, tamper detection, serialization)
- **Trusted time source abstraction** (`src/time_source.rs`)
  - `TimeSource` trait with `SystemTimeSource`, `NtpTimeSource`, `SimulatedTimeSource`
  - `NtpTimeSource` validates NTP sync status and drift tolerance (configurable max)
  - `SimulatedTimeSource` for deterministic testing with `advance()` / `set()`
  - `TrustedTimestamp` records source type and accuracy for audit trails
  - 21 tests (system, NTP sync/drift, simulated, trait objects, serialization)
- **HSM signing — SimulatedHsmProvider** (`src/identity/hsm.rs`)
  - `SimulatedHsmProvider` implements `SigningProvider` with full HSM lifecycle (config, session open/close/reopen, PIN auth, key lookup by label)
  - Session-gated signing: close session prevents signing, reopen with correct PIN restores it
  - Compatible as signer for TSA, OCSP, CRL (integration tested)
  - Cross-verification with `verify_signature` module confirmed
  - Ready for hardware HSM swap — same interface, replace `SimulatedHsmProvider` with `HsmSigningProvider`
  - 17 tests (config, auth, sign/verify, session lifecycle, trait compat, TSA integration, cross-verify)
- **CA Hierarchy — root + intermediate** (`src/pki.rs`)
  - `CaHierarchy` with offline root CA + operational intermediate CA (`pathLenConstraint=0`)
  - `generate()` creates both tiers in memory, intermediate signed by root
  - `sign_node_cert()` issues certs from intermediate, `chain_pem()` for full chain
  - Compatible with CRL generation via intermediate CA
  - 9 tests (generation, key separation, chain PEM, trust store, CRL compat)
- **OCSP Responder — RFC 6960** (`src/msp/ocsp.rs`, `src/api/handlers/ocsp.rs`)
  - `OcspResponder` queries CRL store for certificate status (Good/Revoked/Unknown)
  - Signed responses with Ed25519 or ML-DSA-65, nonce echo, configurable validity
  - `verify_ocsp_response()` cryptographic verification
  - API endpoints: `POST /api/v1/ocsp/query`, `GET /api/v1/ocsp/status/{msp_id}/{serial}`
  - `AppState.ocsp_responder` integration, disabled by default
  - 19 tests (14 unit + 5 E2E endpoint)
- **CRL RFC 5280 generation** (`src/msp/crl_rfc5280.rs`)
  - `generate_crl_der()` and `generate_crl_pem()` via rcgen — proper DER/PEM X.509 CRL signed by node CA
  - `NodeCaConfig::cert()` / `key()` accessors for CRL signing
  - Validated with x509-parser roundtrip (generate DER → parse → verify revoked cert count)
  - Zero new dependencies — uses existing rcgen 0.13 CRL support
  - 9 tests (empty CRL, revoked serials, CRL numbers, PEM markers, invalid hex skip, large CRL, x509-parser roundtrip)
- **Audit tamper-evidence hash chain** (`src/audit.rs`)
  - `AuditEntry` extended with `previous_hash` and `entry_hash` (SHA-256 chain)
  - `seal()`, `verify()`, `compute_hash()` per entry; `verify_audit_chain()` for full chain validation
  - `MemoryAuditStore.append()` auto-seals entries with previous hash link
  - Tampering any entry invalidates all subsequent hashes — detectable in O(n)
  - 10 new tests (chain linking, tamper detection, broken link, determinism, edge cases)
- **Certificate Policy / CPS — RFC 3647 / ETSI TS 102 042** (`src/pki_policy.rs`, `src/api/handlers/policy.rs`)
  - OID namespace under Goya PEN: CP (`1.3.6.1.4.1.99999.2.1`), CPS (`.2.2`), TSA (`.1.1`), Signature Policy (`.3.1`)
  - `CertificatePolicy` with legal framework (Ley 19.799, DS 181, Decreto 24), subscriber/CA/RA obligations, assurance levels, algorithms, revocation mechanisms
  - `CertificationPracticeStatement` with identity proofing policy, key management, certificate profiles (FES/FEA/TSA), audit policy, compliance references
  - API endpoints: `GET /api/v1/policy/cp`, `GET /api/v1/policy/cps`, `GET /api/v1/policy/oids`
  - 17 tests (14 unit + 3 E2E endpoint)
- **Registration Authority (RA) — Ley 19.799 Art. 15** (`src/identity/ra.rs`, `src/api/handlers/ra.rs`)
  - `RaStore` with identity proofing lifecycle: Pending → Verified / Rejected
  - Chilean RUT validation (modulo 11 check digit, format normalization)
  - `IdentityProofing` record: DID, RUT, legal name, proofing method (in-person / video / remote), officer DID, timestamps, rejection reason
  - API endpoints: `POST /api/v1/identity/proof`, `POST .../approve`, `POST .../reject`, `GET .../proof/{did}`
  - `AppState.ra_store` integration, disabled by default
  - 27 tests (11 RUT validation + 11 RA lifecycle + 5 E2E endpoint)
- **XAdES-BES electronic signatures** — ETSI TS 101 903 (`src/signature/xades.rs`)
  - `to_xades_bes()` generates compliant XML envelopes from `SignedEnvelope`
  - `parse_xades_fields()` extracts and validates core fields from XAdES XML
  - SignedProperties: SigningTime (ISO 8601), SigningCertificateV2, ClaimedRole (FES/FEA/FEQ), DataObjectFormat, SignerDID
  - W3C algorithm URIs for Ed25519 and ML-DSA-65 (post-quantum)
  - SignedInfo with document digest reference + SignedProperties digest reference
  - No external XML crate — template-based generation, output in canonical form
  - 20 tests (structure, namespaces, roundtrip, determinism, ISO 8601, base64, algorithms)
- **Time Stamping Authority (TSA) — RFC 3161** (`src/tsa/`, `src/api/handlers/tsa.rs`)
  - `TsaProvider` with monotonic serial counter (`AtomicU64`), configurable accuracy, policy OID
  - `TstInfo` with all RFC 3161 fields: version, policy, hash algorithm, message imprint, serial number, genTime, accuracy, ordering, nonce, TSA name
  - Signing via `SigningProvider` trait — supports Ed25519 and ML-DSA-65 (post-quantum)
  - `verify_token()` cryptographic verification of timestamp tokens
  - API endpoints: `POST /api/v1/tsa/timestamp`, `GET /api/v1/tsa/policy`, `POST /api/v1/tsa/verify`
  - `AppState.tsa_provider` integration, disabled by default
  - 22 tests (16 unit + 6 E2E endpoint)
- **Document integrity verification** — canonical fingerprinting layer (`src/document/`)
  - `DocumentFingerprint`: decomposes a document into 5 hashable dimensions (content, structure, tables, images, metadata) with a merkle root as `canonical_hash`
  - `VerificationReport`: dimensional comparison producing `identical`, `content_match`, `partial_match`, or `no_match` verdicts
  - `POST /api/v1/notarize/verify-document` — compares a candidate fingerprint against a registered notarization, returns per-dimension report with human-readable conclusion
  - Backward compatible: existing hash-based notarization unchanged; fingerprint stored in `NotarizationEntry.metadata.fingerprint`
  - 22 unit tests (merkle root, integrity, all verdict paths, serialization) + 6 E2E tests (endpoint: identical, content_match, partial_match, no_match, 404, 422)

### Fixed

- 31 comprehensive storage tests using hardcoded `/tmp/test_*` paths replaced with `temp_store()` (TempDir auto-cleanup) — fixes RocksDB corruption from stale SST/MANIFEST files between runs

### Changed

- `scripts/gauntlet.sh` — tiered quality gate that runs every existing check as one command, so agent-written code is constrained by tests rather than by review
  - T0 static (`fmt`, `clippy --all-targets`, crypto boundary) · T1 unit + doc · T2 integration suite · T3 coverage threshold · T4 supply chain (`audit`, `deny`) · T5 mutation score · T6 fuzz targets
  - `./scripts/gauntlet.sh` runs T0–T4; `full` adds mutation and fuzzing; a bare tier number runs one tier
  - Thresholds are env-overridable: `COV_MIN`, `MUTANTS_MIN`, `FUZZ_SECS`, `MUTANTS_SCOPE`
  - Baseline on first full run: T0–T2 green (1861 unit + 4 doc + 35 integration suites), coverage 66.51% lines
  - Runs at `JOBS=3` with incremental caching and full debuginfo off. Those two, not job count, were what pushed `target/debug/incremental` to 37 GB and filled the disk — and a full disk surfaces as a bogus `exit 101` "compile failure", so check `df` before believing one
  - `.githooks/pre-push` runs T0+T1 (~1 min warm) before every push — the only gate that runs automatically. Enable with `git config core.hooksPath .githooks`. T2 is left out so the hook stays below the threshold where people reach for `--no-verify`. The existing `.pre-commit-config.yaml` was decorative: `pre-commit` was never installed and `.git/hooks/` was empty
  - `.github/workflows/ci.yml` now runs the gauntlet and is `workflow_dispatch:` only — Actions minutes are a real cost here, so it consumes none unless launched by hand for a clean-room Linux check. Its `push`/`pull_request` triggers had been failing on *every* run because `prost-build` could not find `protoc` and the workflow never installed it, so the four commands it did list were gating nothing. Now installs `protobuf-compiler` + `clang`, and stops pinning "latest nightly" so `rust-toolchain.toml` governs and CI matches local builds
  - T3 (coverage) is excluded from the default run: `llvm-cov` compiles with its own instrumentation flags, so it builds a second full set of artifacts and roughly doubles `target/`. Request it explicitly with `./scripts/gauntlet.sh 3`
  - Fully serial by default (`CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1`, `line-tables-only` debuginfo) — default parallelism peaks past 16 GB on this tree; T2 links one integration binary at a time instead of all 36 at once
- Stripe integration: `POST /api/v1/checkout` (creates Stripe Checkout Session) + `POST /api/v1/stripe/webhook` (handles `checkout.session.completed`)
  - `src/api/handlers/stripe.rs` — direct Stripe REST API via reqwest (no SDK), 3 tiers (starter/business/enterprise), env-driven price IDs
  - Env vars: `STRIPE_SECRET_KEY`, `STRIPE_PRICE_STARTER`, `STRIPE_PRICE_BUSINESS`, `STRIPE_PRICE_ENTERPRISE`
  - Returns 503 with clear message when Stripe not configured (graceful degradation)
- Electronic signature framework: Simple (FES) and Advanced (FEA) with post-quantum cryptography + biometric evidence
  - `src/signature/mod.rs` — `SignatureLevel` (Simple/Advanced/Qualified), `BiometricType` (Fingerprint, FacialRecognition, Rut, Iris, Voice, GovernmentId, extensible), `BiometricEvidence` (SHA-256 commitment, never raw data), `SignedEnvelope`, `compute_biometrics_hash()`
  - Legal alignment: Chile Ley 19.799 (FES/FEA), EU eIDAS 910/2014 (Simple/Advanced/Qualified), US ESIGN Act + UETA
  - FEA requires ML-DSA-65 (FIPS 204, PQC) + at least one biometric commitment bound to signing payload
  - Biometric commitments are order-independent (sorted + hashed) and cryptographically bound to the signature
- ML-DSA-65 signature verification in notarize handler (`verify_mldsa65`, `verify_signature` dispatcher)
- `NotarizeRequest` and `TransferDocumentRequest` accept `signature_level`, `signature_algorithm`, `biometric_evidence` (backwards compatible via serde defaults)
- `NotarizationEntry` and `OwnershipTransfer` storage types carry `signature_level` and `biometric_evidence` (backwards compatible with legacy JSON)
- Context-prefixed signing payloads: Simple `"notarize:{s}:{h}"`, Advanced `"notarize_fea:{s}:{h}:{bio_hash}"`
- Verify/get/list/provenance responses include `signature_level` and `biometric_evidence`
- 36 new tests: 30 signature module (levels, biometrics, envelope, serde, payload determinism, error variants) + 6 storage (roundtrip, backwards compat, list, transfer)
- Shared signature verification module (`src/signature/verify.rs`): `verify_ed25519`, `verify_mldsa65`, `verify_signature` dispatcher, `validate_public_key` — replaces 4 duplicated `verify_ed25519` helpers and 2 inline verifiers across handlers
- Identity `verify_signature` endpoint auto-detects Ed25519 and ML-DSA-65 (was Ed25519-only)
- 15 new tests for shared verification (Ed25519 + ML-DSA-65 sign/verify, dispatch, cross-algo rejection, public key validation)
- System-wide FES/FEA support across all signature-bearing endpoints:
  - `governance.rs`: `CastVoteRequest` — FEA payload `"vote_fea:{id}:{option}:{pk}:{bio_hash}"`
  - `inference.rs`: `SubmitInferenceRequest`, `SubmitProvenRequest`, `ChallengeInferenceRequest` — FEA appends `:{bio_hash}` to existing payloads
  - `alias.rs`: `AliasRegisterRequest`, `AliasRevokeRequest` — FEA appends `:{bio_hash}` to register/revoke payloads
  - `invitations.rs`: `CreateInvitationRequest`, `RespondInvitationRequest` — FEA appends `:{bio_hash}`
  - All request structs accept `signature_level`, `signature_algorithm`, `biometric_evidence` with serde defaults (fully backwards compatible)
- `docs/compliance/ELECTRONIC-SIGNATURE-COMPLIANCE.md` — legal compliance mapping for electronic signatures: Chile Ley 19.799 (FES/FEA), EU eIDAS 910/2014 + eIDAS 2.0 (Simple/Advanced/Qualified), US ESIGN Act + UETA, NIST FIPS 204/186-5/SP 800-63B, GDPR Art. 9/25/35 biometric considerations, Chilean Ley 19.628/21.719 data protection, full endpoint coverage matrix, roadmap
- 6 E2E handler tests: FES notarize+verify, FEA ML-DSA-65+biometric full flow, Advanced+Ed25519 rejected, Advanced without biometric rejected, legacy backwards compat, Qualified+GovernmentId
- `validate_fes_fea()` shared helper in `signature/mod.rs` — validates level↔algorithm, biometric requirement, commitment format, public key size
- Storage types `Vote`, `AliasEntry`, `InferenceClaim`, `Invitation` now persist `signature_level`, `signature_algorithm`, `biometric_evidence` (serde defaults for backwards compat)
- `VoteStore::set_vote_signature_data()` — attaches FEA metadata to votes after casting

### Security

- `tests/service_e2e.rs` no longer writes to a live node by default. `SEED_URL` was hardcoded to `https://goya-node.fly.dev`, so a plain `cargo test` notarized documents and created on-chain records on the deployed node — silently, with no opt-in and no way to redirect it. The URL now comes from `GOYA_E2E_URL` and all 13 tests are `#[ignore]`d, so they report as *ignored* rather than as passing no-ops:

  ```
  GOYA_E2E_URL=https://goya-node.fly.dev cargo test --test service_e2e -- --ignored
  ```

- Dependency audit: 12 known vulnerabilities reduced to 5, none of which have a fix reachable from this tree
  - `cargo update` closed 7, including `quick-xml` RUSTSEC-2026-0194/0195 (both 7.5 high — memory exhaustion and quadratic attribute parsing), `wasmtime` RUSTSEC-2026-0114 (5.9) and `crossbeam-epoch` RUSTSEC-2026-0204. The fixes were already published upstream; the lockfile was simply pinned to older versions
  - `reqwest` 0.11 → 0.12, moving the node's HTTP client onto the rustls 0.23 stack. Its feature is `rustls-tls-webpki-roots-no-provider`, not `rustls-tls`: the latter enables reqwest's own ring-backed provider alongside the aws-lc-rs one installed by `tls::install_crypto_provider()`, and rustls 0.23 panics rather than choose between two. That collision broke 25 TLS unit tests, which is how it was caught — production already installs a provider explicitly at startup, so only test binaries were affected
  - The 5 remaining are listed individually in `.cargo/audit.toml`, each naming the crate that blocks it: `protobuf` 2.x (pinned by `raft` 0.7, the latest published release), `rustls-webpki` 0.101 ×3 (pinned by `tauri` 2.11.5 → `reqwest` 0.11, reachable only from the desktop app — the node's own P2P TLS uses rustls 0.23), `tracing-subscriber` 0.2 (pinned by `revm` → `ark-bn254` → `ark-relations`). Marked for re-review 2026-10-27
  - 27 `unmaintained` advisories remain as warnings, notably `pqcrypto-mldsa`/`-mlkem`/`-traits` (upstream PQClean being archived) — relevant to the FIPS 204 posture, tracked but not vulnerabilities

### Fixed

- **Dead code cleanup in `rate_limit.rs`** — removed 4 `#[allow(dead_code)]` suppressions and a stale TODO that suggested wiring a global middleware. Rate limiting is per-handler by design. 2 TDD tests guard against regression
- **PQC test evidence doc corrected** — `PQC-TEST-EVIDENCE.md` had a TODO and an invalid multi-arg `cargo test` command. Replaced with correct commands and updated test count from claimed 12 to actual 74 (2 main + 72 pqc_crypto_module). 2 TDD tests enforce correctness
- **138 bare `Mutex::lock().unwrap()` replaced with poison-recovering locks** — production code across 7 modules now uses `.unwrap_or_else(|e| e.into_inner())` instead of panicking on mutex poisoning. TDD tests enforce no bare `.unwrap()` in production code
- **Stripe webhook ponytail formalized** — tier activation deferral tightened to standard `ponytail:` format with upgrade trigger

### Tests

- **93 new tests** (1869 → 1962), covering trust-boundary rejection paths, pure logic, and real-world use cases:
  - `signature/verify.rs` (15→21): malformed signature/key rejection — bad hex, wrong length, invalid Ed25519 point, ML-DSA-65 variants
  - `notarize.rs` (6→22): invalid hash, DID↔pubkey mismatch, invalid signature, duplicate hash, non-owner transfer, FEA validation, sign_fea rejection
  - `governance.rs` (0→11): empty/null-byte proposer, quorum bounds, voting period zero, empty voter, proposal not found
  - `inference.rs` (2→23): `resolve_outputs` tolerance modes, `parse_numeric_output`, `parse_vector_output`, `cosine_similarity`, `build_inference_payload`
  - `contracts.rs` (0→12): ERC-20 rate limiter, param helpers, contract not found, unknown function, missing params
  - `invitations.rs` (0→6): empty/excess proposals, unknown alias, missing voter param, unknown invitation, list empty
  - `alias.rs` (1→6): invalid commitment/salt format, resolve/by-did/revoke not found
  - `credentials.rs` (1→6): get/verify/revoke not found, unknown issuer, store_get not found
  - `use_cases.rs` (new, 6 E2E): real-world vertical tests proving functional PQC DLT — document notarization (FES), firma electrónica simple (Ed25519), firma electrónica avanzada (ML-DSA-65 + fingerprint + RUT biometric), governance proposal lifecycle, credential issue→verify→revoke→verify(invalid), ownership transfer with provenance chain

### Changed

- **Honest naming: "ZKP" → "commitment"** — the commitment-based attribute verification module never was zero-knowledge (the verifier sees the claim value), so the public API now says what it actually is:
  - Types: `ZkPresentation` → `CommitmentPresentation`, `ZkProof` → `CommitmentProof`, `ZkpError` → `CommitmentError`
  - Endpoints: `/api/v1/identity/zkp/prove|verify` → `/api/v1/identity/commitment/prove|verify`
  - Handler functions: `prove_zkp`/`verify_zkp` → `prove_commitment`/`verify_commitment`
  - SERVICE-CATALOG.md and service-catalog.json: "zero-knowledge proofs" → "commitment-based attribute verification"
  - ROADMAP: clarifies current state is commitment-based, ZK real (Bulletproofs/PLONK) is future work
  - 3 TDD tests enforce the rename: `types_are_named_commitment_not_zk`, `no_false_zk_claims_in_production_code`, `struct_doc_says_commitment_not_zk`
  - **Breaking:** clients using `/identity/zkp/prove` or `/identity/zkp/verify` must update to `/identity/commitment/prove|verify`
- **Honest throughput claims** — `ONE-PAGER-PRODUCTO.md` presented the 18,700 TX/s Solo ordering micro-benchmark as the system's throughput. Now shows both: motor interno ~18,700 TX/s and measured E2E ~42 TPS (rate-limited) / ~71 TPS single connection. `tests/doc_honesty.rs` (3 tests) enforces that any mention of 18,700 in commercial docs includes a qualifier word (`motor`, `ordering`, `interno`, etc.)
- **Compliance doc honesty** — `ELECTRONIC-SIGNATURE-COMPLIANCE.md` now carries:
  - Self-assessment disclaimer: explicitly states this is not a certification or formal audit
  - Biometric limitation: commitments are unverified, client-asserted SHA-256 hashes — no liveness detection, no template verification, no trusted capture device
  - eIDAS Art. 26(b) caveat: self-issued DIDs differ from identity-verified credentials; full compliance requires external identity verification
  - SP 800-63B AAL2: reclassified as structural analogy, not equivalence — AAL2 requires verified biometric enrollment through a trusted provider
  - 4 new tests in `tests/doc_honesty.rs` enforce these disclaimers going forward

### Security

- **Stripe webhook HMAC verification** — `POST /api/v1/stripe/webhook` now verifies `Stripe-Signature` header (HMAC-SHA256) before processing events. Previously accepted any POST without verification.
  - Requires `STRIPE_WEBHOOK_SECRET` env var; returns 503 when not configured (fail-closed, was silently accepting everything)
  - Returns 401 on signature mismatch with `INVALID_SIGNATURE` error code
  - `checkout.session.completed` handler logs explicitly that tier activation is NOT IMPLEMENTED — no silent success
  - 5 TDD tests: missing secret rejected, missing header rejected, invalid HMAC rejected, valid HMAC accepted, tampered payload rejected

### Changed

- **E2E service tests documented as excluded** — `tests/service_e2e.rs` (13 tests) writes to a live node and is deliberately excluded from the gauntlet. `gauntlet.sh` now documents this exclusion with the exact command to run them manually. 3 TDD tests enforce: all tests have `#[ignore]`, module doc explains `GOYA_E2E_URL` + `--ignored`, gauntlet mentions `service_e2e`.
- **"production-ready" claim qualified** — `FABRIC-COMPARISON.md` (archived) stated "rust-bc is production-ready" without qualification. Replaced with "functional completeness" language that acknowledges operational readiness factors (load testing, DR, SLAs) are outside the scope of a feature comparison. 2 TDD tests: one scans non-archive docs, one targets the Fabric comparison specifically.
- **ML-KEM-768 qualified as TLS opt-in** — commercial docs and regulatory sandbox presented ML-KEM-768 as a core always-on feature. It is actually X25519+ML-KEM-768 hybrid key exchange at the TLS layer, activated only with `TLS_PQC_KEM=true`. Updated: PLATFORM-ARCHITECTURE.md, HORIZONTAL-CAPABILITIES-REPORT.md, COMPLIANCE-LEY-21663-CIBERSEGURIDAD.md, `regulatory/sandbox.rs`. 2 TDD tests in `tests/doc_honesty.rs` enforce the qualifier.
- **eIDAS Qualified rejected at API level** — `SignatureLevel::Qualified` was accepted by all endpoints but treated identically to Advanced (no QTSP, no qualified certificate, no QSCD). Now rejected with `SignatureError::QualifiedNotSupported` in `validate_fes_fea()`, which all 10 signature-bearing endpoints call. Returns 400 with message "Qualified signature level requires a Qualified Trust Service Provider (QTSP) — not yet supported". The enum variant remains for future use when a certified TSP is integrated.
  - 1 TDD test in `signature::tests`: `validate_fes_fea_rejects_qualified`
  - E2E test `e2e_qualified_notarize_accepted` → `e2e_qualified_notarize_rejected` (asserts 400)
- Handlers `notarize`, `alias`, `inference`, `invitations`, `governance`, `identity` now use shared `crate::signature::verify_*` — eliminated ~228 lines of duplicated verification code
- All 10 signature-bearing endpoints validate FES/FEA constraints: level↔algorithm match, biometric evidence required for Advanced, public key size per algorithm, biometric commitment format
- `alias.rs` and `invitations.rs` use shared `validate_fes_fea()` instead of inline validation (eliminated 4 duplicated ~40-line blocks)
- Identity `verify_signature` endpoint dispatches by `signature_algorithm` field (was blind try-both hack)
- Governance, inference, alias, invitations handlers now pass FEA data through to storage (was silently discarded)

### Fixed

- 12 `IdentityRecord` constructors missing `public_key` field in `stress.rs`, `adapters.rs`, `memory.rs`, `comprehensive_tests.rs`
- `tests/cross_subsystem.rs` did not compile — 13th `IdentityRecord` constructor missed by the `public_key` migration, plus an unused `OracleError` import. CI only builds `--lib` and `--test crypto_boundary`, so the breakage went unnoticed. 7 tests green again.
- 9 clippy errors surfaced by `--all-targets` (in-file `#[cfg(test)]` modules were never linted): unused imports in `consensus/backend.rs`, `api/handlers/channels.rs`, `api/handlers/proposals.rs`, `discovery/auto.rs`; `clone()` → `std::slice::from_ref` in `forensic.rs` and `signature/mod.rs`; manual range checks → `RangeInclusive::contains` in `stress.rs`; inconsistent digit grouping in `registry/tokenization.rs`
- `rustfmt` drift in `api/handlers/stripe.rs`
- `tests/bft_e2e.rs` equivocator never equivocated — it computed a conflicting block hash, then discarded it and cast only the honest vote, so `e2e_safety_under_equivocation_across_100_rounds` and `e2e_7_nodes_tolerates_2_byzantine` passed without any equivocation occurring. It now casts both conflicting votes; all 16 tests still pass, confirming the vote collector deduplicates by `voter_id`
- `tests/chaos_network.rs` `assert_honest_convergence()` was written but never called. Now asserted in the 5 scenarios that can converge; the 3 that cannot (partition, crash-recovery, message-drop) document why — this harness does not simulate `StateRequest`/`StateResponse` catch-up, so missed blocks are never reconciled
- Dead test scaffolding removed: `Replayer` node behavior (never constructed; replay is covered by `scenario_4` via `replay_old_blocks()`), `SimNode.decided`/`.outbox`, `TestNode.store`, `FloodNode.id`/`.signing_provider`
- 11 further clippy errors in `tests/` — never linted before because the gate omitted `--all-targets`

## [0.3.0] — 2026-06-29

**Wallet, governance, and security hardening**

### Added

- Desktop wallet: balance query, testnet faucet (1000 GOYA), signed transfers, transaction history
- Desktop governance: list proposals, create text proposals, cast signed votes, view tally
- E2E test suite (12 tests, 70+ assertions against live seed node): notarization, concurrency, 10MB documents, signer isolation, impersonation attacks, malformed payloads, wallet flow, governance flow

### Security

- Unified DID derivation to `did:goya:{pubkey_hex[..16]}` across all endpoints
- Notarize endpoint rejects requests where signer DID does not match public key
- Governance votes verified with DID↔pubkey binding
- Canonical `did_from_pubkey_hex()` and `did_matches_pubkey()` in `identity::did`

### Changed

- Seed node rate limits increased (50 RPS, 500 RPM, 10000 RPH) for E2E suite stability

## [0.2.0] — 2026-06-29

**Accounts, replay protection, signed notarization, and CI**

### Added

- `GET /api/v1/accounts/{address}` — wallet-compatible endpoint returning balance and nonce
- `store_nonce` helper deriving outbound transaction count per address
- Nonce field on `CreateTransactionRequest` with replay protection validation
- Coinbase transactions (`from: "0"`) exempt from balance check for test funding
- CI workflow restored (fmt, clippy, tests, crypto boundary) — free on public repo

### Changed

- DID scheme renamed from `did:cerulean:` to `did:goya:` across all code, tests, scripts, and docs
- Desktop app now targets Windows (NSIS + MSI) in addition to macOS (DMG)
- Local identity store uses `%APPDATA%\goya\` on Windows instead of `~/.goya/`
- Generated platform icons (ICO, ICNS, PNG variants) from source PNG via `cargo tauri icon`
- `pqc_crypto_module` memory locking now cross-platform: `mlock` on Unix, `VirtualLock` on Windows

### Fixed

- Desktop notarization now signs with Ed25519, matching server's payload verification
- Notarize UI requires identity selection and password before submitting

## [0.1.0] — 2026-06-24

**Light client mode and desktop app (GOYA-ledger for Mac)**

### Added

- `NodeMode` enum (`Full`/`Light`) via `NODE_MODE` env var
- `LightRoutes`: Starter-tier endpoints (notarize, identity, credentials, audit, chain, ZKP, alias, health)
- `SeedProxy`: forwards requests to a remote full node via `SEED_NODE_URL`
- `LocalIdentityStore`: JSON-file persistence for DIDs (`~/.goya/identities.json`)
- Tauri v2 macOS desktop app (4.5MB `.dmg`, Apple Silicon)
- Password-encrypted private keys (Argon2id + AES-256-GCM)
- Drag-and-drop document notarization
- Seed node on Fly.io (`goya-node.fly.dev`) with RocksDB persistent volume

### Fixed

- Replaced deprecated `std::env::home_dir()` with `dirs::home_dir()`
- Removed flaky env-mutating tests (parallel race condition)

### Changed

- Enforced crypto boundary in `tauri-app` (SHA-256 via `pqc_crypto_module`)
- Fly.io storage switched from memory to RocksDB with persistent volume

### 2026-06-21

**Credential risk scoring, vault hardening, bridge API**

Credential intelligence:
- Extended `RiskInput` with 4 credential-specific fields: `issuer_verified`, `credential_count_by_issuer`, `credential_age_days`, `issuer_reputation`
- Added 4 scoring rules: unverified issuer (+25), bulk issuance (+20), expired credential (+15), low reputation (+30)
- Added `CredentialMill` pattern detection — flags DID issuers producing credentials above threshold

Vault hardening:
- Per-IP rate limiting on vault recovery (5 attempts per 5-minute window)
- Explicit audit logging with `VaultOperation` action type and operation metadata
- Vault secret fingerprint logged at startup for rotation verification
- Recovery without configured secret returns proper error instead of generic 404

Bridge API:
- 5 new endpoints: `POST /bridge/transfer`, `POST /bridge/inbound`, `GET /bridge/transfer/{id}`, `GET /bridge/chains`, `GET /bridge/balances/{account}`
- ACL-enforced (peer/Propose) for write operations
- Validation via iterator-based pattern (no `if` statements)
- Made `BridgeEngine::compute_message_id` public for handler use

**Residual risk elimination**

- Wired audit store to RocksDB when `STORAGE_BACKEND=rocksdb` — audit entries now persist across restarts
- Removed unused JWT_SECRET infrastructure (dead code — mTLS is the only auth mechanism)
- Added 30s timeout to chaincode external HTTP calls, 10s to registry adapter and CouchDB client
- Restricted `/pentest/report` and `/stress/report` endpoints to admin-only via ACL
- Fixed flaky CORS env-var test (parallel test race condition)
- Measured coverage baseline: 66% lines, 58% functions (unit tests only)

**Production readiness hardening**

Security & resilience:
- Replaced all `lock().unwrap()` in API handlers (oracle, evm, contact) with poison-safe `unwrap_or_else`
- Replaced `panic!()` in `BoxedVerifier::clone` with reject-all fallback verifier
- CORS: added `CORS_ALLOWED_ORIGINS` env var; fixed invalid `allow_any_origin + supports_credentials` combo
- Production guards: `RUST_BC_ENV=production` now requires TLS; warns if `ACL_MODE=permissive`

Rate limiting & timeouts:
- Per-endpoint rate limiting: write-heavy endpoints (transactions, gateway, contracts) get half the baseline limits
- Explicit HTTP timeouts via `HTTP_KEEP_ALIVE_SECS` and `HTTP_REQUEST_TIMEOUT_SECS` env vars
- Configurable mempool capacity via `MEMPOOL_MAX_SIZE` env var (default 1000)

Pagination:
- Audit, governance proposals, and credentials list endpoints now use `PaginatedResponse` (max 100 items/page)

Logging:
- Migrated from `env_logger` to `tracing-subscriber`; `LOG_FORMAT=json` enables structured JSON output

CI/CD:
- Added GitHub Actions workflow: fmt, clippy, unit tests, crypto boundary, cargo-deny
- Added coverage job with `cargo-llvm-cov`

Documentation:
- `docs/api/RUNBOOKS.md` — 5 operational procedures (node recovery, chain repair, performance, security, escalation)
- `docs/api/INTEGRATION-GUIDE.md` — API-first client integration guide with curl/fetch/Python examples
- `docs/api/PERFORMANCE-BASELINE.md` — load test procedure and SLA targets
- Updated `docs/api/configuration-guide.md` with all new env vars and production security requirements

### 2026-06-19

**API services one-pager**

- Added `docs/commercial/ONE-PAGER-SERVICIOS-API.md` — single-page enterprise services overview (7 API capabilities, benchmarks, differentiators)
- HTML template and PDF version included for print/email distribution

### 2026-06-18

**Block lookup by hash and real chain verification**

- `GET /blocks/{hash}` — finds a block by its SHA-256 hash (linear scan over BlockStore)
- `GET /chain/verify` — walks the full chain validating `parent_hash` linkage; reports `first_invalid_height` on failure
- `GET /chain/info` — returns the real SHA-256 hash of the latest block instead of a placeholder
- Removed fake `difficulty` field from `ChainInfoResponse` (not applicable to BFT/DPoS consensus)
- Shared `compute_block_hash` and `hex_hash` utilities in `chain.rs` for consistent block hashing
- All 49 API handler modules now contain real business logic (0 scaffolds remaining)

**Legacy storage removed — unified BlockStore path**

All storage now flows through the `BlockStore` trait. The original in-memory
blockchain, wallet manager, and mempool have been deleted (~1,500 lines).

Removed files:
- `src/blockchain.rs` — in-memory Block, Blockchain, PoW mining
- `src/models.rs` — Transaction, Wallet, WalletManager, Mempool
- `src/storage/compat.rs` — legacy-to-modern type conversion shim

AppState:
- Removed `blockchain`, `wallet_manager`, `mempool` fields
- Wallet creation now uses `SigningProvider` keypair generation
- Staking uses BlockStore balance instead of WalletManager lookup

P2P network:
- Removed legacy message variants: `GetBlocks`, `Blocks`, `NewBlock`, `NewTransaction`
- Removed `Node.blockchain` and `Node.wallet_manager` fields
- Sync migrated to `StateRequest`/`StateResponse`
- Gossip propagates `OrderedBlock` instead of legacy `Block`
- `Version` handshake reads height from `BlockStore`

Crypto boundary:
- Migrated `cerulean.rs`, `governance.rs`, `stress.rs` from raw `sha2`/`ed25519_dalek` to `pqc_crypto_module::legacy::*`
- All 5 pre-existing crypto boundary violations resolved

Net change: **−2,200 lines**

### 2026-06-13

**API scaffold migration — legacy router eliminated**

- Migrated all legacy endpoints to scaffold handlers (`src/api/handlers/`):
  - `billing.rs` — API key create/deactivate/usage (3 endpoints)
  - `wallets.rs` — balance, create, transaction history (3 endpoints)
  - `network.rs` — peers, connect, sync, mine (4 endpoints)
  - `stats.rs` — system statistics (1 endpoint)
  - `airdrop.rs` — claim, tracking, statistics, eligibility, history, tiers (7 endpoints)
  - `contracts.rs` — ERC-20 + ERC-721 deploy, execute, queries (18 endpoints)
- Utilities (health, version, openapi) registered in scaffold router
- Staking deduplication: removed legacy handlers, scaffold is the single source
- `api_legacy.rs` collapsed from ~2250 lines to 13 (only `config_routes` delegating to scaffold)
- Removed 16 dead scope helper methods and empty `identity_routes()` from `routes.rs`
- Removed `#[allow(dead_code)]` from `ApiRoutes` impl block
- All handlers now use typed `ApiError`, `ApiResponse` with trace ID, and `enforce_acl`

### 2026-06-08

**AWS hosting decommissioned**

- Cerulean-only AWS resources removed: EC2, CloudFront, S3 buckets, Route53 zone, ACM cert, security groups, key pair, orphan EBS
- Domain `ceruleanledger.com` deletion initiated (pending registrant email authorization)
- Deploy scripts updated: no hardcoded IPs or retired S3 bucket; remote targets via `DEPLOY_HOST` / `RELEASE_URL` env vars
- `SECURITY.md` contact updated: email → GitHub Security Advisories
- `interop.rs` instrument URL → GitHub repository
- `Dockerfile.prebuilt` S3 pull reference → local cross-compile
- `test-inference.sh` default host → localhost

### 2026-05-30

**Notarization — Proof of Existence service**

- `POST /api/v1/notarize` — register a document hash with Ed25519 signature verification
- `GET /api/v1/notarize/verify/{hash}` — verify a document hash exists on-chain
- `GET /api/v1/notarize/{id}` — get notarization by ID
- `GET /api/v1/notarize` — list notarizations (filter by `?signer=`)
- `NotarizationEntry` type: id, content_hash, signer, metadata, timestamp, block_height, signature
- Storage: `notarizations` column family (RocksDB) with `hash:` secondary index
- Signing payload: `"notarize:{signer}:{content_hash}"` — signer bound to signature to prevent impersonation
- Duplicate detection: returns 409 error if hash already notarized
- Document never leaves client — only SHA-256 hash is submitted

**Originality verification report and reproducible audit script**

- `docs/INFORME-ORIGINALIDAD-CERULEAN-LEDGER.md` — forensic comparison against `Alefrank76/cerulean-dlt-framework`
- `scripts/verify-originality.sh` — reproducible 8-step verification script any third party can run
- Covers: temporal precedence, framework incompatibility, line-by-line diff, struct/function signatures, SHA-256 checksums
- Result: 4 trivial matches out of 215 non-trivial lines (1.9%), all generic Rust field declarations

---

### 2026-05-22

**Optimistic ML Oracle — Phase 4 (zkML Bridge)**

- `POST /api/v1/inference/submit-proven` — submit claim with ZK proof, instant finalization (no dispute window)
- `ProofVerifier` trait: pluggable verification interface for different proof systems
- `MultiVerifier`: dispatches proofs to the correct backend by `ProofType`
- Shipped verifier: `Sha256CommitmentVerifier` (baseline integrity proof, not ZK)
- Proof types defined: `Sha256Commitment`, `Groth16Bn254`, `PlonkBn254`, `StarkFri`
- `AppState.proof_verifier` wired for runtime configuration
- Future: plug in ezkl (Groth16) or Risc0 (STARK) for real ZK verification

**Optimistic ML Oracle — Phase 3 (Non-deterministic models)**

- `OutputTolerance` enum: `Exact` (hash match), `Numeric{threshold}` (absolute difference), `Cosine{min_similarity}` (vector similarity)
- Claims declare their tolerance mode at submit time; resolution uses it during challenges
- Numeric: parses `{"result": N}` or raw number, compares within threshold
- Cosine: parses `[f64]` arrays or `{"embedding": [...]}` / `{"vector": [...]}`, computes cosine similarity
- Falls back to exact hash comparison if outputs can't be parsed
- Backward compatible: `Exact` is the default, all Phase 1/2 claims unchanged

**Optimistic ML Oracle — Phase 2 (Disputes)**

- `POST /api/v1/inference/challenge` — challenge a pending claim with re-executed output
- Resolution: outputs match → challenge rejected (oracle correct); outputs differ → oracle slashed
- Challenger must be staked (bond), cannot self-challenge, must be within dispute window
- Oracle reputation updated: double penalty on slash, reward on rejected challenge
- `InferenceChallenge` type with `succeeded` field
- Signing payload: `"challenge:{claim_id}:{challenger_output_hash}"`
- Config: `INFERENCE_CHALLENGE_BOND` (default 1000)

**Optimistic ML Oracle — Phase 1 (MVP)**

- `POST /api/v1/inference/submit` — submit inference claim (staked oracle, Ed25519 signed)
- `POST /api/v1/inference/finalize/{id}` — finalize claim after dispute window (permissionless)
- `GET /api/v1/inference/claims` — list claims (filter by status, oracle, model)
- `GET /api/v1/inference/claims/{id}` — get claim details
- `GET /api/v1/inference/models` — list known models with claim counts
- `InferenceClaim` type with `ClaimStatus` enum (Pending → Finalized)
- Storage: `inference_claims` column family (RocksDB) with `oracle:` and `model:` secondary indices
- Signing payload: `"inference:submit:{model_hash}:{output_hash}"`
- Config: `INFERENCE_DISPUTE_WINDOW_SECS` (default 24h), `INFERENCE_MIN_ORACLE_STAKE` (default 5000)

**Context-prefixed signing payloads for alias endpoints**

- Register signs `"alias:register:{commitment}"`, revoke signs `"alias:revoke:{commitment}"`
- Prevents cross-endpoint replay (previously both signed the raw commitment)
- **Breaking:** wallets must update their signing payload format

**Staking endpoints migrated to `/api/v1` scaffold**

- `POST /api/v1/staking/stake` — stake tokens to become a validator
- `POST /api/v1/staking/unstake` — request unstaking (lock period)
- `POST /api/v1/staking/complete-unstake` — complete unstaking after lock period
- `GET /api/v1/staking/validators` — list active validators
- `GET /api/v1/staking/validator/{address}` — get validator info
- `GET /api/v1/staking/my-stake/{address}` — get own stake info
- Uses `ApiResponse<T>` envelope, `enforce_acl`, and `tx_pool` (consistent with scaffold)
- Legacy routes at `/staking/*` still exist but are superseded

**Fast deploy pipeline**

- `scripts/deploy.sh` — single command: cross-compile → scp → docker rebuild on EC2
- sccache integrated in `Cross.toml` for cached cross-compilation (~6s incremental vs ~12min cold)
- Docker build now uses layer cache (no `--no-cache`), rebuilds in ~1s

**Alias reverse lookup by DID**

- `GET /alias/by-did/{did}` — resolve a DID to its active alias (commitment, encrypted alias, registration date)
- Returns 404 if no alias exists, 410 if revoked
- Uses existing `read_alias_by_did()` storage method (RocksDB `did:` secondary index)

---

### 2026-05-21

**Alias registry — zero-knowledge alias system**

- `POST /alias/register` — register alias commitment (SHA3-256) with Ed25519 signature verification
- `POST /alias/resolve` — resolve commitment to DID + address; returns 410 if revoked
- `POST /alias/revoke` — owner-only revocation with 15-day cooldown before re-registration
- One alias per DID; duplicate commitment returns 409
- `AliasEntry` type: commitment, DID, salt, encrypted alias, status, timestamps
- Storage: `aliases` column family (RocksDB) with `did:` secondary index for reverse lookup

**Invitation system — governance proposal invitations via alias**

- `POST /governance/invitations` — create invitation linked to alias commitment
- `GET /governance/invitations?voter={commitment}` — list pending invitations
- `POST /governance/invitations/respond` — accept or reject with Ed25519 signature
- Rate limit: max 5 invitations per hour per DID, max 20 proposals per invitation
- `Invitation` type with response tracking (responded, accepted)
- Storage: `invitations` column family (RocksDB)

**Deploy pipeline — local cross-compilation**

- `Cross.toml` added for macOS → Linux amd64 cross-compilation
- `reqwest` switched to `rustls-tls` (eliminates dynamic `libssl` dependency)
- Deploy flow: cross-compile locally → scp binary → `Dockerfile.prebuilt` rebuild (~3 min)

**Repo cleanup**

- Removed 7 obsolete scripts (legacy SQLite architecture)
- Removed 12 disabled CI workflow files
- Removed `docs/book/` (empty mdBook stubs), duplicate PDFs, redundant API reference
- Removed `Dockerfile.static`, `docker-compose.yml`, `docker-compose.deploy.yml` (unused)
- Archived `docs/camara/`, `docs/es/`, architecture comparisons, client PDFs → `docs/archive/`
- Moved `ALIAS_API.md`, `ALIAS_DESIGN.md` → `docs/architecture/`

---

### 2026-05-19

**Vault recovery via passphrase-derived key (NIST SP 800-185)**

- `POST /vault/store` now accepts optional `recovery_key` (64 hex chars, client-derived via KDF)
- `POST /vault/recover` — recover wallet by recovery key; returns DID + encrypted wallet
- Server-side blind index via HMAC-SHA3-256 prevents brute-force on DB leak
- `VAULT_RECOVERY_SECRET` env var enables recovery (disabled when absent)
- `hmac_sha3_256()` added to `pqc_crypto_module` public API
- Storage trait: `write_vault_recovery()` / `read_vault_by_recovery()` with MemoryStore and RocksDB implementations
- Recovery key validated as exactly 32 bytes hex; wrong key returns 404

**Release distribution pipeline**

- `scripts/install-cerulean.sh` — one-line installer for Linux servers (systemd service, zero dependencies)
- `scripts/build-release.sh` — disposable EC2 spot build (~$0.03 per release)
- `Dockerfile.prebuilt` — runtime-only image from precompiled binary (no compilation)
- Binaries hosted at `s3://ceruleanledger-releases/` *(retired 2026-06)*
- Production downsized from t3.medium to t3.small ($15/mo)

---

### 2026-05-17

**Legacy storage removal — API layer fully migrated to BlockStore**

New modules:
- `src/mining.rs` — MiningService backed by BlockStore (replaces Blockchain::mine_block_with_reward)
- `src/transaction/mempool.rs` — TransactionPool using storage::Transaction (replaces models::Mempool)
- `src/storage/compat.rs` — From<> conversions between legacy and new types
- `src/api/handlers/governance_entities.rs` — 14 CRUD endpoints for scopes, assemblies, sessions, actas
- `BlockStore::calculate_balance()`, `transactions_for_address()` — default impls for handler migration

Legacy files removed:
- `state_reconstructor.rs`, `state_snapshot.rs`, `pruning.rs`, `block_storage.rs`
- `fee_validation_test.rs`, `integration_test.rs` (tested legacy Blockchain directly)

Handlers migrated to BlockStore:
- `mine_block` — uses MiningService exclusively
- `get_wallet_balance`, `get_wallet_transactions` — read from BlockStore
- `get_stats` — reads chain data from BlockStore
- `create_transaction` — validates and enqueues via TransactionPool
- `stake`, `unstake`, `claim_airdrop` — create storage::Transaction directly
- `list_blocks`, `get_block_by_index` — read from BlockStore
- `verify_chain`, `get_blockchain_info` — read from BlockStore
- `health_check`, `get_version` — read height from BlockStore

Legacy types (`blockchain.rs`, `models.rs`) are now `pub(crate)` — not exported, only used internally by `network/mod.rs` for P2P sync (not exercised in single-node mode).

RocksDB column families added: `scopes`, `assemblies`, `sessions`, `actas`.

Governance entity CRUD (20 endpoints):
- Scopes, assemblies, sessions, actas: POST, GET, GET/{id}, PUT/{id}, DELETE/{id}

Security fixes:
- Blocks signed with node's SigningProvider (Ed25519/ML-DSA-65)
- `POST /transactions` rejects unsigned non-coinbase transactions
- TransactionPool double-spend prevention via `add_checked()` (validates pending spend vs balance)
- Blind voter ID nonce: `sha256(proposal_id || voter_did || client_nonce)` prevents brute-force deanonymization

Enterprise core modules (`src/registry/`):
- Asset Registry: 10 endpoints — asset CRUD, event history, bulk telemetry ingestion, node-signed certified export
- RWA Tokenization: 5 endpoints — asset tokens with collateral lifecycle (Free/Pledged/Released/Seized)
- Compliance Automation: 6 endpoints — configurable rules, bulk evaluation against asset events, result history

CI workflows disabled (renamed to `.yml.disabled`).

---

### 2026-05-16

**Repo cleanup and v0.1.0 release**

- Extracted frontends and SDKs to dedicated repos
- Removed 60 obsolete scripts, 9 test binaries, 160+ stale docs
- Removed `num_cpus` dependency, dead functions, `tesseract/` prototype
- Slimmed `CLAUDE.md` from 385 to 91 lines
- Rewrote `README.md` with Cerulean Ledger branding
- Tagged `v0.1.0`

---

## [0.1.0] — 2026-05-16

### 2026-05-16

**Monorepo cleanup — extract frontends and SDKs to dedicated repos**

- Removed `block-explorer-vite/`, `cerulean-voto/`, `sdks/` from monorepo
- Each now lives in its own GitHub repo: [cerulean-explorer](https://github.com/clementeaf/cerulean-explorer), [cerulean-voto](https://github.com/clementeaf/cerulean-voto), [cerulean-sdks](https://github.com/clementeaf/cerulean-sdks)
- Added extracted directories to `.gitignore` to prevent residual artifacts
- Updated `CLAUDE.md` to reference dedicated repos instead of local paths

---

### 2026-05-15

**Cerulean Voto — Multi-tenant platform with wallet integration and interoperability**

Vault-backed wallet portability:
- Wallets stored on-chain via `POST /vault/store`, retrieved with `GET /vault/{did}`
- Cross-app: wallet created in Voto is available in Wallet app (and vice versa)
- localStorage is a cache — vault on-chain is the source of truth
- Import existing wallet by DID from any Cerulean app

Chrome extension support:
- Detects `window.cerulean` injected by Cerulean Wallet extension
- One-click connect: gets address + publicKey, registers DID, no passphrase needed
- Setup step 1: three tabs (Extension / Tengo DID / Crear nueva)

Wallet-name separation:
- Wallet = pure crypto (DID + keypair), no name
- Name = padron label, assigned by admin when adding to organization
- DID derived from address (`sha256(pubkey)[0..20]`), not raw public key slice

Dynamic scopes (multi-tenant organizational structure):
- Generic `Scope` model: name, label (user-defined type), parent, channel, members
- No imposed hierarchy — each institution defines its own structure
- Members with roles: admin, voter, observer per scope
- Each scope = own DLT channel with isolated data
- Tree-propagated permissions: founder = root admin, admin role inherits downward

Setup wizard (5-step guided onboarding):
- Step 1: Create wallet or connect existing (extension / DID import / new)
- Step 2: Organization (name, RUT, president, secretary → auto-creates DLT channel)
- Step 3: Inscribe participants by address/DID (admin doesn't create wallets for others)
- Step 4: Organizational structure (optional scopes with DLT channels)
- Step 5: First election (optional)

Governance persistence:
- `write_proposal`/`write_vote` added to BlockStore trait
- MemoryStore and RocksDB implementations
- Migration v2→v3: proposals and votes column families

Vault endpoints:
- `POST /api/v1/vault/store` — store encrypted wallet blob by DID
- `GET /api/v1/vault/{did}` — retrieve encrypted wallet backup
- RocksDB vault column family for persistent storage

Voter history endpoint:
- `GET /api/v1/governance/votes?voter={did}` — all proposals where voter participated
- Searches by raw DID and blind voter ID (for signed votes)

UI/UX overhaul:
- Voters: expandable rows with QR code, DID, address, public key, wallet download
- Vote: receipt with DID, payload SHA-256, Ed25519 signature, 5 animated guarantees
- Actas: green "Anclada" / amber "Pendiente" badge, DID on-chain link
- Admin: interop cards (DID Resolution, VC, JSON-LD, OpenAPI), DLT channel management
- Scopes: tree view with role badges, permission-gated member management
- Layout: active scope indicator in header bar

---

**Cerulean Voto — Real wallet, vote secrecy, acta anchoring, W3C interoperability**

Wallet integration (cerulean-wallet WASM):
- Ed25519 wallet generation via WASM (Argon2id + AES-256-GCM, same crypto as CLI)
- DID derived from public key: `did:goya:{sha256(pk)[0..20]}`
- Vote signing with passphrase-protected private key
- Backend verifies Ed25519 signature + DID-to-pubkey binding before accepting vote

Vote secrecy:
- Blind voter ID: `sha256(proposal_id || voter_did)` stored instead of real identity
- Cross-proposal unlinkability, deduplication preserved
- Unsigned votes (legacy/permissive) unchanged

Acta blockchain anchoring:
- SHA-256 hash stored as `did:goya:acta:{folio}` on session close
- Acta UI shows trace_id and anchoring status

Voter registry:
- Padron persisted in localStorage with real wallet files
- Vote page validates against registered padron (dropdown, not free text)
- Agenda items linkable to governance proposals

W3C Interoperability:
- `GET /did/{did}` — DID Resolution (did-core), Ed25519VerificationKey2020
- `GET /credentials/{id}/vc` — Verifiable Credential (VC Data Model 2.0)
- `GET /governance/proposals/{id}/export` — JSON-LD (schema.org VoteAction)
- OpenAPI 3.0.3: 66 paths, governance + interop endpoints documented
- Content types: `application/did+ld+json`, `application/vc+ld+json`, `application/ld+json`

Cleanup:
- Removed unused `PageIntro` component, 5 dead types, 2 unused API functions
- 1712 tests pass

---

### 2026-05-14

**Cerulean Voto — Asambleas, Sesiones, Actas, Administracion**

- 4 new modules: Asambleas, Sesiones, Actas, Administracion
- localStorage-backed store (`store.ts`) with correlative numbering
- Sidebar grouped into 3 sections: Votacion, Organizacion, Administracion
- Ley 19.418 Art. 16: convocatoria date/method, deadline validation (5d ordinaria, 3d extraordinaria)
- Ley 19.418 Art. 16: first/second citation quorum, quorum validation with legal warning
- Ley 19.418 Art. 17: actas with folio, org identification (name + RUT), president/secretary signatures
- ISO 15489: actas are permanent records (no delete), SHA-256 integrity hash per acta
- ISO 8601: all dates and timestamps in standard format
- Auto-generated acta on session close with all legally required fields
- Admin panel: org settings, signatory management, quorum config, normativa reference, export/import backup
- Schema migration support: `read()` merges with defaults for backward compatibility

---

### 2026-05-13

**Production deployment — S3/CloudFront + EC2 backend** *(retired 2026-06)*

- Frontend hosting migrated to S3 + CloudFront (Explorer + Voto)
- Domain `ceruleanledger.com` registered with ACM SSL certificate
- Explorer: `https://ceruleanledger.com`
- Voto: `https://voto.ceruleanledger.com`
- API proxied through CloudFront `/api/*` → EC2 node
- EC2 runs only node + Prometheus + Grafana (t3.medium, us-east-1)

**Deploy infrastructure**

- `docker-compose.deploy.yml`: Caddy TLS, strict ACL, parameterized secrets
- `deploy/Caddyfile`: reverse proxy with security headers
- `.env.deploy.example`: secrets template (JWT, HMAC, Grafana password)
- `.gitignore`: added `.env` files and Caddy data directories
- Seed script accepts `API_URL` env var for remote seeding
- Dockerfile healthcheck supports both HTTP and HTTPS modes

**CI fixes**

- Added `protoc` to performance-guardrails, security-audit, nightly-chaos, pre-lab-audit workflows
- `cargo audit --ignore-yanked` for transitive yanked dependencies (keccak via revm)
- Fixed `signature_algorithm` missing field in `full_benchmark.rs`, `tps_benchmark.rs`, `ordering_throughput.rs`

**Benchmark report** (`docs/architecture/benchmarks/SANDBOX-BENCHMARK-REPORT.md`)

- 10/10 stress modules passed (crypto: 6.6M ops/s, storage: 48K ops/s)
- 40 pentest scenarios: 37 blocked, 3 detected, 0 vulnerable
- Health latency: 20ms avg

---

### 2026-05-12

**Institutional UI overhaul — All modules redesigned for flagship demo**

- Governance: full-width proposal table + slide-in drawer with tally bar, vote buttons, crypto proof
- Credentials: full-width document table + drawer with status banner, content, crypto proof
- Compliance (Audit Trail): category-based filters (Identity, Documents, Governance, Blockchain, Errors), human-readable Spanish labels, domain events by default, sticky thead with internal scroll, drawer detail with ISO 27001 compliance info
- System Health: auto-loading dashboard (replaces empty chaincode lookup) — overview cards, infrastructure checks, regulatory compliance bar, stress performance grid
- Sidebar: "Compliance" → "Cumplimiento", "Audit Trail" → "Registro de Operaciones", "Chaincode Health" → "Salud del Sistema"
- Global smooth transitions: 150ms cubic-bezier on all elements, fade-in animation on panel selection, backdrop fade on drawers
- Backend: `list_credentials()` added to BlockStore trait, MemoryStore, RocksDbBlockStore; `GET /api/v1/store/credentials` endpoint
- API client: `listCredentials()` function

---

**Digital Identity module — Document signing with legal validity**

- `/identity` rewritten as institutional digital identity module: identities list + signed documents panel + document detail drawer
- Documents presented as contracts, titles, certificates — not technical credentials
- Each document shows: signer, date, status (Vigente/Expirado/Revocado), content, and cryptographic proof (ML-DSA-65, SHA-256, blockchain seal)
- Backend: `list_identities()` added to `BlockStore` trait, `MemoryStore`, and `RocksDbBlockStore`; `GET /api/v1/store/identities` endpoint
- `/demo` (RRHH verification) redesigned: horizontal step indicator, single active card, compact layout without scrollbar
- Layout: sidebar groups Red and Tokens hidden for institutional focus
- API client: `listIdentities()` function, `Credential` type extended with `claims` and `status` fields

---

**Identity & Governance Hardening — Zero-panic, bounded, validated**

- Governance handlers: 6 `unwrap()` replaced with proper 503 error responses (zero panic paths)
- Tally arithmetic: `saturating_add`/`saturating_mul` on all vote power accumulation (overflow-safe)
- Voting period: `saturating_add` on `voting_ends_at` calculation
- Identity: hex decode fallback removed — invalid hex returns 400 instead of silent bypass
- Input limits: proposer/voter/delegate max 256B, description max 4KB, title max 256B, param changes max 50 entries
- Empty string rejection: voter, proposer, delegator, delegate, veto caller all validated non-empty
- Semantic param validation: quorum/threshold 1-100, voting_period > 0
- Issuer DID existence check before credential issuance (both `issue_credential` and `store_write_credential`)
- Stress tests: `stress_identity` (DID write+read cycle) and `stress_credential` (credential write+read cycle) added — 10 modules total
- Pentest suite: 33 → 40 scenarios. New: oversized description, empty voter, quorum=0, credential without issuer, vote spam (1000 votes), delegation cycle, signature bypass via invalid hex. All BLOCKED.
- Tests: 1687 passed, 0 critical vulnerabilities

---

**Institutional Integrity Dashboard — Flagship monitoring panel**

- New page `/integridad` — real-time platform integrity dashboard for institutional stakeholders
- 8 horizontal service cards: Security (pentest), Forensic (hash chain), Compliance (21 regulatory checks), Cryptography (PQC/KAT), Storage (RocksDB), Consensus (BFT/validators), Oracles (feed freshness), Intelligence (AML/risk)
- Each card opens a slide-in drawer with full service detail (scenarios, checks, metrics, validators)
- Tabbed right panel: integrity report table + security events timeline
- Stress test performance grid (8 modules: ops/s, p99 latency, status)
- Vertical control cards linking to Credentials, Governance, Finance, Contracts subsystems
- Print CSS for PDF export of integrity reports
- API client: 10 new typed functions (health, version, regulatory, pentest, stress, forensic, oracle status)
- Layout: `h-screen` fixed layout, sidebar sticky with internal scroll, no page-level scrollbar
- Sidebar: new "Integridad" group as primary navigation item
- Zero new dependencies, zero backend changes — all data from existing 44 monitoring endpoints

---

**Production Readiness — Load testing scripts and audit engagement package**

- `tools/k6/load-test.js` — k6 load test suite: 4 scenarios (default, spike, soak, stress), 8 weighted API actions (health, stats, blocks, mempool, audit, identity, wallet+mine), p95 < 500ms and error rate < 1% thresholds, JSON reports
- `docs/SECURITY-AUDIT-ENGAGEMENT.md` — complete engagement package for external auditor: scope (10 components prioritized), architecture summary, crypto inventory (8 algorithms), 6 known risks, internal security work summary, key files for review, environment setup

**Schema Migrations — Versioned RocksDB upgrades on startup**

- `src/storage/migrations.rs` — migration system: schema version in `meta` CF, migration registry with `(version, fn)` entries, runs pending on startup
- Fresh databases stamped at `LATEST_VERSION` (v2) without running migrations
- Existing databases migrate incrementally (v1→v2 verifies new CFs exist)
- Idempotent: crash mid-migration re-runs same step on next startup
- Wired in `main.rs` — migrations run before serving requests, fatal on failure
- 6 unit tests: fresh DB, v1→v2, idempotent, version survives reopen, sorted order

**Graceful Shutdown — Real WAL flush and full task cleanup**

- `RocksDbBlockStore::flush_wal()` — flushes WAL + memtables to SST files before exit
- Shutdown handler now aborts 5 background tasks (was 3): added pull_sync, antientropy
- Per-phase shutdown logging with elapsed time for operator visibility
- 2 unit tests: flush on empty DB, flush persists writes across reopen

**Consolidation — AppState test builder, cross-subsystem tests, legacy deprecation docs**

- `AppState::test_default()` — single constructor with all memory-backed defaults for tests. Replaces ~50-line duplicated constructors across 6 handler test files + unused imports cleaned up.
- `tests/cross_subsystem.rs` — 7 integration tests crossing module boundaries: identity→credential→audit, chaincode→sandbox→audit, legal oracle→audit, credential→ZKP verification, credential revocation→ZKP invalidation, multi-org audit isolation
- Legacy storage (`src/blockchain.rs`) documented as DEPRECATED with migration path in CLAUDE.md. 17 production refs remain in `api_legacy.rs` — both systems operate independently without conflicts.

**Consolidation — Stubs replaced, honest labeling, real HTTP, RocksDB persistence**

- Identity handlers: `create_identity` generates real DID + Ed25519 keypair + persists to store; `get_identity` reads from store; `rotate_key` updates record; `verify_signature` performs real Ed25519 verification
- Credential handlers: `issue_credential` persists to store; `get_credential` reads from store; `verify_credential` checks status + expiry + revocation; `revoke_credential` updates status with audit event
- ZKP module renamed to "commitment-based attribute verification" — docs honestly state verifier sees claim value
- Legal oracle: stub fetch replaced with real `reqwest::blocking` HTTP client (15s timeout, Bearer auth, error handling)
- RocksDB persistence for 3 new stores: `AuditStore` (CF `audit_log`), `SandboxReportStore` (CF `sandbox_reports`), `OracleRecordStore` (CF `oracle_records`). All use existing Column Family pattern in `adapters.rs`. `SandboxReportStore` refactored from concrete struct to trait (`MemorySandboxReportStore` + `RocksDbBlockStore` impl).

**ZKP for Sovereign Identity — Commitment-based attribute verification**

- `src/identity/zkp.rs` — Commitment-based ZKP: SHA-256(value || blinding) proofs without revealing claim data
- 3 predicates: `RangeProof` (numeric >= threshold), `SetMembership` (value in allowed set), `CredentialValidity` (active, not expired/revoked)
- `prove_range()`, `prove_set_membership()`, `prove_credential_validity()` generate `ZkPresentation`
- `verify_presentation()` validates commitment integrity + predicate satisfaction; rejects tampered proofs
- Endpoints: `POST /identity/zkp/prove`, `POST /identity/zkp/verify`
- Audit events on each verification (result only, no claim data revealed)
- 13 unit tests covering all predicates, boundary cases, and tamper detection

**Legal Oracle — Off-chain legal data queries with on-chain records**

- `src/legal_oracle/mod.rs` — `OracleRecord` (source, query, response_hash, timestamp, signature, summary), `OracleRecordStore` trait + `MemoryOracleRecordStore`, SHA-256 response hashing
- `src/legal_oracle/legal.rs` — `LegalOracle` service: configurable sources, injectable fetch function, TTL cache, response hash verification, JSON summary extraction
- Endpoints: `POST /oracle/legal/query`, `GET /oracle/legal/records`, `GET /oracle/legal/records/{id}`
- Audit event emitted on each query
- 15 unit tests (store CRUD, cache hit/miss, hash verification, fetch errors, summary extraction)

**Forensic Dashboard — Compliance UI in block explorer**

- Compliance page (`/compliance`): audit events table with action/org filters, 5 summary indicators (total, blocks mined, DID mutations, chaincode deploys, failed requests), auto-refresh 10s, color-coded action badges
- ChaincodeHealth page (`/chaincode-health`): sandbox report viewer per chaincode version, pass/fail summary card, per-check detail (well-formedness, import whitelist, memory limits)
- API client: `getAuditEvents()`, `getSandboxReport()` with types `AuditEntry`, `SandboxReport`
- Sidebar: new "Compliance" nav group with Audit Trail and Chaincode Health items

**Chaincode Sandbox — Static validation gate before deployment**

- `src/chaincode/sandbox.rs` — Wasm static analysis: well-formedness (wasmparser), import whitelist (6 allowed host functions), memory limits (max 16 pages / 1 MB)
- Auto-detects WAT text vs binary Wasm
- `SandboxReport` struct with per-check results, wasm size, validation duration
- `SandboxReportStore` in-memory for persisting reports per chaincode version
- Gate in `install_chaincode`: rejects Wasm that fails sandbox with 400 + failure details
- `GET /api/v1/chaincode/{id}/sandbox-report?version=...` — query validation report
- Dependencies: `wasmparser = "0.236"`, `wat = "1.246"`
- 10 unit tests (valid, malformed, forbidden imports, oversized memory, boundary, store)

**Audit — Action-level domain events (ISO 27001 compliance)**

- `AuditEntry.action` field with 16 semantic action types (`AuditAction` enum: `BlockMined`, `DidRegistered`, `ChaincodeInstalled`, etc.)
- `AuditStore::query()` now accepts `action` filter alongside existing `org_id` and time range filters
- `emit_domain_event()` / `emit_if_present()` helpers for emitting audit events from business logic without HTTP context
- Domain audit hooks in 8 mutation handlers: mine_block, create_wallet, stake, install_chaincode, store_write_identity, store_write_credential, create_channel, submit_proposal
- `GET /api/v1/audit/requests?action=block_mined` — query by action type
- CSV export includes action column
- `AuditEntry.metadata` optional field for domain-specific context (block height, DID, chaincode hash, etc.)
- 11 unit tests covering action filtering, combined filters, domain event emission, and display formatting
- Integration roadmap: `docs/ROADMAP-INTEGRACION-CERULEAN.md` — 5 phases derived from Abraxas integration guide, adapted to actual architecture

### 2026-05-10

**Enterprise Sandbox**

- Prometheus + Grafana added to sandbox compose (pre-provisioned dashboard at `:3000`)
- Resource governance: memory/CPU limits on all containers (node 512M, frontends 128M)
- Rich seed data: 7 wallets, 8 blocks, wallet transfers, 2 orgs, 2 channels, 7 DIDs, 5 credentials, governance proposals with votes
- Version tracking: `BUILD_VERSION` from git SHA injected at build time
- Nginx error fallback: branded 502/503 page with 5s auto-retry when node is starting
- SSE event stream proxy through nginx (unbuffered, long-lived connections)
- Multi-org demo: org1 (Universidad de Chile) + org2 (Banco Central), channels `academic` + `financial`
- Backup/restore script: `scripts/sandbox-backup.sh` snapshots RocksDB volume as tarball

**Oracle System Hardening**

- Fix: `aggregate_reports` now filters by symbol (was mixing all pending reports)
- Fix: HMAC signature always verified (removed test-mode bypass for timestamps < 100M)
- Fix: constant-time comparison via `Mac::verify_slice` (prevents timing attacks)
- Fix: external connector uses fixed-point pricing (×10^8) for sub-1 tokens (CLP/USD)
- Fix: `retain` only clears processed symbol's reports (other symbols persist)

**Pentest Suite Expanded (20 → 33 scenarios)**

Network layer attacks (PEN-021 to PEN-023):
- Sybil peer flooding: `MembershipTable` now enforces `MAX_PEERS` cap (default 500), rejects excess
- Malformed P2P messages: serde rejects garbage/truncated/oversized payloads without panic
- Eclipse attack: DAG rejects blocks referencing non-existent parents

EVM adversarial tests (PEN-025, PEN-026, PEN-031, PEN-032):
- Reentrancy: revm enforces 1024 call depth + gas limit
- Storage collision: address-scoped storage isolation verified
- Delegatecall abuse: separate contracts cannot modify each other's state remotely
- Gas bomb: infinite loop + memory expansion halts cleanly at gas limit

Consensus attacks (PEN-027, PEN-028):
- Nothing-at-stake: equivocation detector catches dual-fork proposals, slashing applies
- Long-range reorg: BFT commit QC provides finality; without QC, fork choice acknowledged

Economic attacks (PEN-024, PEN-029, PEN-030, PEN-033):
- Front-running sandwich: MVCC conflict detector separates overlapping txs into waves
- Validator grinding: stake-weighted round-robin gives no advantage to address splitting
- Fee suppression: `MIN_BASE_FEE` floor prevents zero-fee exploitation
- Proposer-MEV: deterministic scheduling + multi-org endorsement prevents extraction

Infrastructure:
- `MembershipTable::with_capacity()` constructor for custom peer limits
- `record_alive_full()` now returns `bool` (false = rejected at capacity)

Tests: 1,629+ passed, 0 critical vulnerabilities.

---

**Oracle Maturation**

- External connector wired in `main.rs` — `ORACLE_SOURCES` env var activates real HTTP price feeds
- New env var `ORACLE_CONNECTOR_SYMBOL` (default `BTC/USD`) selects the feed symbol
- API responses now include `age_ms` and `is_stale` fields for every price feed
- New endpoint: `GET /oracle/status` — node count, feed count, stale/fresh breakdown, pending reports

**Pentest Suite Expanded (15 → 20 scenarios)**

Strengthened existing tests (previously descriptive, now exercise real code):
- PEN-003: Replay attack — `MemoryStore` rejects duplicate block height
- PEN-004: Double-spend — `schedule_batch` detects WAW conflict, separates into sequential waves

New attack scenarios:
- PEN-016: Path traversal in channel names (`../`, null bytes) — HashMap keys are literal, no leakage
- PEN-017: Oracle price manipulation (20x outlier) — filtered by median, consensus unaffected
- PEN-018: Governance vote with zero stake — `VoteStore` rejects `ZeroPower`
- PEN-019: Credential forgery with untrusted issuer — detected, distinguishable by DID
- PEN-020: Oversized payload (100KB ISO 20022 message) — no panic, size limits recommended at boundary

**Sandbox Seed Data**

- `scripts/seed-sandbox.sh` — pre-loads 5 wallets, 5 blocks, 5 identities, 3 credentials, 1 governance proposal, 1 contact entry
- Auto-runs after node health check in `scripts/sandbox.sh`
- Idempotent: safe to run multiple times

Tests: 1,604 passed, 0 failures.

### 2026-05-09

**Adversarial Pentest Suite**

15 attack scenarios executed against live code (`src/forensic_pentest.rs`):
- Block tampering, signature forgery, replay, double-spend, equivocation
- ACL bypass, rate limit evasion, channel crossing, identity spoofing
- Hash collision, timestamp manipulation, overflow, null injection, key extraction, state rollback
- 2 real vulnerabilities found and fixed:
  - `SecurityToken::mint` integer overflow → `checked_add`
  - `MemoryStore::write_block` allowed overwrites → duplicate height rejection
- API: `GET /pentest/report`
- 0 critical vulnerabilities remaining

**Forensic, Intelligence, Stress — Full API Exposure**

- Forensic: `GET /forensic/replay`, `GET /forensic/integrity` (block chain verification)
- Intelligence: `POST /intelligence/anomaly`, `POST /intelligence/risk`, `POST /intelligence/patterns`
- Stress: expanded to 8 modules (+ governance, forensic, pattern detection)

**Pre-Launch Modules (5/5 Complete)**

Intelligence layer (`src/intelligence/`):
- Anomaly detection: rolling z-score with configurable threshold and window
- Risk scoring: 6 rules (watchlist, KYC, amount, frequency, identity age, country)
- Pattern recognition: velocity spike, structuring, round-trip, dormant activation

Oracle E2E (`src/oracle_demo.rs`):
- Simulated BTC/USD, ETH/USD, CLP/USD feeds with deterministic pseudo-random walk
- Background poller wired into OracleRegistry via `ORACLE_DEMO=true`
- Queryable via `GET /oracle/feeds`

Regulatory sandbox (`src/regulatory/`):
- 21 compliance checks across 10 categories
- Automated report with SHA-256 content hash
- API: `GET /regulatory/checks`, `GET /regulatory/report`

Forensic audit — replay and integrity:
- `replay_blocks()`: sequential height verification, gap detection
- `verify_chain_integrity()`: hash linkage check, tampering detection

Per-module stress testing (`src/stress.rs`):
- 5 targeted tests: storage, crypto, anomaly, risk, ISO 20022 validation
- Per-module ops/sec, p50/p99 latency, Pass/Degraded/Fail classification
- API: `GET /stress/report?ops=1000`

**Contact Form Backend**

- `POST /api/v1/contact` — stores name, email, org, message
- `GET /api/v1/contact` — admin-only listing
- Landing CTA replaced with inline form posting to own node

**Landing Page Redesign — Non-Technical, Identity-Driven**

Complete rewrite of `block-explorer-vite/src/pages/Landing.tsx`:
- Hero: "La confianza deja de ser una promesa" — original concept, not borrowed
- Live network pulse: fetches `/api/v1/health` every 10s, shows block height + peers
- Three-column thesis: integrity by design, privacy without sacrifice, operational sovereignty
- Four verticals as interactive selector with per-use headline and 3-step mini-flow
- Hard numbers: 18,700 TX/s, 14ms p50, 1,532 tests, 58 components, 193 ISO countries
- Real social proof: Cámara Blockchain Chile audit quote (not fabricated logos)
- Subtle visual identity: `#fafbfc` background, clean typography, generous spacing
- No comparisons, no competitor mentions, no copied patterns

**Oracle, Forensic, Compliance — HTTP API Endpoints**

- Oracle: `GET /oracle/feeds/{symbol}`, `GET /oracle/feeds`, `GET /oracle/nodes`
- Forensic: `GET /forensic/timeline`, `GET /forensic/security`, `POST /forensic/export`
- Compliance: `POST /compliance/validate/{pacs008,pacs002,pacs004,pain001,pain002,camt053,camt052}`, `GET /compliance/countries`, `GET /compliance/currencies`
- `oracle_registry` added to AppState

**ISO Compliance — Full Standard Coverage**

- ISO 20022: 7 message types (pacs.008/002/004, pain.001/002, camt.053/052)
- ISO 3166: expanded to 193 countries
- ISO 4217: expanded to 64 currencies with 3-decimal support
- ISO 8601: date, datetime, duration validators
- ERC-3643: security tokens with identity registry, compliance module, issuer controls

**Auto-Discovery, Pricing**

- Gossip-based peer exchange (`src/discovery/auto.rs`)
- Pricing structure draft (`docs/commercial/PRICING.md`)

**Cerulean Voto — Vote Privacy**

- `POST /vote` returns tally only (no individual votes)
- `GET /votes` restricted to admin role (403 for others)

Tests: 1,532 passed, 0 failures.

### 2026-05-08

**CSIRT Webhook Notifier & Security Events**

- 5 security event variants in `BlockEvent`: `AclDenied`, `EquivocationDetected`, `RateLimitExceeded`, `InvalidSignature`, `ValidatorSlashed`
- `is_security_event()` filter for CSIRT/SIEM forwarding
- `WebhookNotifier` (`src/events/webhook.rs`): subscribes to EventBus, filters security events, POSTs to configurable endpoint with exponential backoff
- Env vars: `CSIRT_WEBHOOK_URL`, `CSIRT_WEBHOOK_SECRET`, `CSIRT_WEBHOOK_TIMEOUT_SECS`
- Wired in `main.rs` — activates only when `CSIRT_WEBHOOK_URL` is set

**Channel Retention Policy**

- `RetentionPolicy` struct: `block_retention_count`, `private_data_ttl_blocks`, `transaction_retention_secs`
- Integrated in `ChannelConfig` with `#[serde(default)]` for backwards compatibility
- `ConfigUpdateType::SetRetention` — configurable via governance config transactions

**Governance Permissive Mode**

- Stake/deposit check skipped in `ACL_MODE=permissive` for proposal submission
- Voter power defaults to 1 in permissive mode (enables sandbox demos without staking)

**Cerulean Voto — UI Overhaul**

- Removed all page titles (sidebar provides context)
- Elections: create form moved to slide-over drawer, history table with internal scroll
- Vote: inline voter bar with per-election buttons, disabled when no name entered
- Vote receipt overlay with animated guarantee checks (signed, immutable, consensus, PQC)
- Voters (Padrón): compact inline registration + verification, no exposed DIDs
- Results: compact cards with tally bars and stats
- All pages: `h-screen` layout with internal scroll, no page-level scrolling
- Borders softened (`border-neutral-100`), shadows removed, padding reduced
- `did:goya:` prefix hidden from all user-facing inputs — DIDs generated internally
- "Deposito" / "Garantia" field removed from elections (hardcoded internally)
- "Peso del voto" removed — 1 person = 1 vote

**Sandbox Infrastructure**

- `docker-compose.sandbox.yml` — single-node + explorer + voto compose
- `block-explorer-vite/Dockerfile` + `nginx.conf` — containerized frontend with API proxy
- `cerulean-voto/Dockerfile` + `nginx.conf` — same for voting app
- `scripts/sandbox.sh` — one-command launcher with Cloudflare Quick Tunnels
- `SANDBOX.md` — guide for quick tunnels and custom domain setup

**Commercial Documentation**

- `COMPLIANCE-LEY-21663-CIBERSEGURIDAD.md` + PDF — Ley 21.663 compliance mapping
- `ONE-PAGER-PRODUCTO.md` — non-technical product explanation
- `POLYGON-COMPARISON.md` — Cerulean vs Polygon positioning
- `VERTICAL-HORIZONTAL-MATRIX.md` — how verticals consume platform capabilities
- `GO-TO-MARKET-STRATEGY.md` — 5-step adoption playbook
- `GOVERNANCE-OPERATIONAL.md` — operational governance framework for regulators
- `SLA.md` — 3-tier service level agreement
- `PRODUCT-GAPS-AND-READINESS.md` — 19 gaps identified, 8 closed this session

Tests: 1445 (18 new), 0 failures. All quality gates pass.

### 2026-05-03

**E2E Distributed Demo — PQC ML-DSA-65 Validated**

Connected all subsystems into a functional distributed demo:

- PQC block signing via pluggable `SigningProvider` (Ed25519 or ML-DSA-65)
- Raft ordering: synchronous commit after propose (no async wait)
- Peer replication: `OrderedBlock` broadcast to all connected peers
- TX indexing: gateway writes transactions to store, queryable by `GET /tx/{tx_id}`
- Smart contract execution: `POST /chaincode/{id}/invoke` with shared world state
- Explorer API: `GET /blocks`, `GET /blocks/{height}` (no channel enforcement)
- Strict algorithm validation: unknown `SIGNING_ALGORITHM` values panic (no silent fallback)
- Block signature verification via `verify_block_signature()` dispatching by algorithm
- Gateway and API now share the same store instance (fixes query-after-commit)
- 7 RocksDB test failures fixed (hardcoded `/tmp/` paths → `tempfile::TempDir`)
- Demo compose: `docker-compose.demo.yml` (3 nodes, ARM64 native, PQC, no TLS)
- Scripts: `demo-consistency.sh`, `demo-persistence.sh`
- Contract: `contracts/kv_store.wat` (set/get demo)
- Docs: `DEMO.md` (10-min onboarding), `docs/dev/LOCAL-DLT-TESTING.md`

Tests: 1427 lib (0 failures), all quality gates pass.

### 2026-04-28

**Pre-Lab Findings Closure — All 11 Findings Resolved**

ML-KEM-768 real implementation:
- `pqcrypto-mlkem` v0.1.1 replaces SHA3-based placeholder (F-001 CLOSED)
- Real keygen/encapsulate/decapsulate: pk=1184B, sk=2400B, ct=1088B, ss=32B
- KAT self-test verifies shared secret roundtrip + invalid ciphertext rejection
- 8 unit tests in `mlkem.rs`

ACVP dry-run harness:
- `tools/acvp_dry_run/` rewritten: 6 modules (vectors, sha3, mldsa, mlkem, report, main)
- 3 JSON vector files: SHA3-256 (5), ML-DSA-65 (5), ML-KEM-768 (5)
- CLI: `--algorithm`, `--vectors`, `--all` flags; generates `report.json`
- 15/15 vectors pass; 5 integration tests (F-002 CLOSED)

Security Policy and documentation:
- `SECURITY_POLICY.md` expanded to 16 sections: CO Guide, User Guide, Error Recovery (F-010, F-009 CLOSED)
- `MODULE_SPECIFICATION.md` created: 9 sections with full API surface (F-008 CLOSED)
- SP 800-90B justification added to `ENTROPY_RNG_EVIDENCE.md` (F-003 CLOSED)
- Boundary documentation clarified in `legacy.rs` (F-006 CLOSED)

Code hardening:
- `libc::mlock` on `MldsaPrivateKey`, `MlKemPrivateKey`, `MlKemSharedSecret` (F-004 CLOSED)
- `is_valid_transition()` + 14 exhaustive FSM tests covering all 16 (state, transition) pairs (F-007 CLOSED)
- Reproducible build verified: hash `29af517b` matches across 2 independent builds (F-011 CLOSED)

CI updates:
- `pre-lab-audit.yml` adds `cargo test -p acvp_dry_run` + `cargo run -p acvp_dry_run -- --all`
- ACVP report.json uploaded as artifact

Audit status: 0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW open. 1 INFO accepted (F-005).
Traceability: 8 PASS, 4 PARTIAL, 0 FAIL.
Tests: 69 pqc_crypto_module + 5 ACVP + 1427 lib = 1501 total.

**Pre-Lab Mock Audit Package**
- `pre_lab_audit/` — 9 documents: mock audit report, ACVP dry-run plan, IG checklist, clean-room build, entropy/RNG evidence, vendor evidence, traceability matrix, findings register
- Mock audit: 0 CRITICAL, 2 HIGH (ML-KEM placeholder, ACVP vectors), 2 MEDIUM, 2 LOW, 3 INFO
- Traceability matrix: 11/12 requirements PASS, 1 PARTIAL (ML-KEM)
- `tools/acvp_dry_run/` — ACVP test vector harness (SHA3, ML-DSA, ML-KEM dry-run)
- `scripts/clean_room_build.sh` — reproducible build verification
- `.github/workflows/pre-lab-audit.yml` — FIPS pre-lab CI workflow

**CI Reliability Hardening**
- `tests/test_seeds.rs` — shared deterministic seed constants for reproducible chaos/property tests
- `.config/nextest.toml` — cargo-nextest profiles: default (no retry), chaos (1 retry, 120s timeout), ci
- `.github/workflows/coverage.yml` — cargo-llvm-cov coverage report on PR + push main
- `scripts/ci_runtime_report.sh` — PR gate timing budget script (target: ≤15 min)
- PR pipeline runs fast critical gates only (no chaos/fuzz/benchmarks)
- Nightly pipeline runs full adversarial validation + benchmarks
- Fix: `fips_readiness` test correctly targets `pqc_crypto_module` crate

**Self-Auditing CI Pipeline**
- 5 GitHub Actions workflows: `ci.yml` (updated with PQC tests), `security-audit.yml`, `performance-guardrails.yml`, `nightly-chaos.yml`, `fuzz.yml`
- `tests/property_invariants.rs` — 7 proptest invariants (tampering invalidates sigs, equivocation always detected, hash collision resistance, serde roundtrip preserves PQC metadata, consistency catches all mismatches)
- `fuzz/` — 3 libfuzzer targets (block parser, signature parser, gossip message parser)
- `deny.toml` — dependency policy (vulnerable=deny, unmaintained=warn, license allowlist)
- CI env: strict PQC mode on all jobs (`REQUIRE_PQC_SIGNATURES=true`, `HASH_ALGORITHM=sha3-256`)

**CMVP Submission Readiness Package**
- `fips_submission/` — complete CMVP intake package for FIPS 140-3 lab engagement
- `SUBMISSION_CHECKLIST.md` — 15 artifacts tracked (10 ready, 2 needs work, 3 not started)
- `LAB_SELECTION.md` — 5 NVLAP-accredited labs profiled (Acumen, atsec, UL, Leidos, InfoGard)
- `TEST_VECTOR_PLAN.md` — ML-DSA, ML-KEM, SHA3, RNG vector requirements and ACVP gaps
- `BUILD_ENVIRONMENT.md` — Rust toolchain, target platforms, deterministic build instructions
- `GAP_ANALYSIS.md` — 7/10 areas aligned, 2 partial (vectors, RNG), 2 missing (CAVP, lab tooling)
- `VALIDATION_TIMELINE.md` — 5-phase plan, 12-24 month estimate, $80K-$250K range
- `CONTACT_PACKAGE/` — executive summary, module overview, 21 questions for initial lab call

**Pre-CMVP FIPS 140-3 Documentation Package**
- `SECURITY_POLICY.md` — finalized 13-section security policy (module ID, boundary, algorithms, roles, services, FSM, self-tests, zeroization)
- `DESIGN_DOCUMENT.md` — architecture diagram, API entry points, data flow, internal components
- `FINITE_STATE_MODEL.md` — 4-state machine with transitions, forbidden paths, fail-closed behavior
- `KEY_MANAGEMENT.md` — key types, generation, storage (in-memory only), usage, ZeroizeOnDrop destruction
- `SELF_TEST_DOCUMENTATION.md` — 4 KATs (SHA3, ML-DSA, ML-KEM, RNG), failure behavior
- `NON_APPROVED_USAGE.md` — legacy algorithms, runtime guard + feature flag gating
- `OPERATIONAL_GUIDANCE.md` — initialization, configuration, error handling, monitoring
- `build/reproducible_build.md` — Rust toolchain pinning, Cargo.lock, deterministic builds
- `build/module_boundary_definition.md` — files inside/outside boundary, enforcement mechanisms
- `tests/fips_readiness.rs` — 8 tests: pre-init rejection, approved ops, legacy blocking, state transitions, fail-closed, no-panic

**Approved vs Legacy Crypto Separation**
- Runtime guards on all legacy functions: `ensure_not_approved()` blocks Ed25519, SHA-256, HMAC when module is in Approved mode
- Guarded functions: `legacy_ed25519_verify`, `legacy_ed25519_sign`, `legacy_sha256`, `legacy_hmac_sha256`
- `approved-only` Cargo feature flag excludes legacy module at compile time
- 12 tests in `approved_vs_legacy.rs`: legacy blocked in approved, works before init, no fallback, API cleanliness
- `SECURITY_POLICY_DRAFT.md` updated with non-approved algorithm enforcement section

**100% Crypto Boundary Compliance**
- All 28 legacy files migrated from direct crypto imports to `pqc_crypto_module::legacy::*`
- `LEGACY_ALLOWLIST` is now empty — 189/189 files (100%) clean
- `pqc_crypto_module::legacy` re-exports Ed25519, SHA-256, HMAC, rand, ML-DSA raw access as explicitly non-approved APIs
- Boundary test fails if any production file imports raw crypto crates directly
- Ed25519/SHA-256 still available for legacy block verification, but routed through the crypto module boundary

**FIPS-Oriented Crypto Module**
- `crates/pqc_crypto_module/` — standalone crate isolating all PQC cryptography behind a strict boundary
- Approved-mode state machine: `Uninitialized → SelfTesting → Approved → Error`
- All crypto APIs reject calls unless module is in `Approved` state
- ML-DSA-65 sign/verify (FIPS 204), SHA3-256 (FIPS 202), ML-KEM-768 placeholder (FIPS 203)
- Startup KAT self-tests for all algorithms + continuous RNG test
- `ZeroizeOnDrop` on all private key and shared secret types
- No classical algorithm fallback — Ed25519, SHA-256, RSA excluded from module API
- `SECURITY_POLICY_DRAFT.md` aligned with FIPS 140-3 Security Policy structure
- 17 integration tests: API boundary, self-tests, no-fallback, key zeroization
- Workspace configuration: root `Cargo.toml` adds `[workspace]` with `crates/pqc_crypto_module`

**Post-Quantum Readiness — Full Stack Hardening**

Crypto-agility layer:
- `signature_algorithm: SigningAlgorithm` field added to `Block`, `DagBlock`, `Endorsement`, `AliveMessage`, `TransactionProposal` (replaces size-based heuristic detection)
- `hash_algorithm: HashAlgorithm` field added to `Block` (enables migration without breaking old blocks)
- `secondary_signature` + `secondary_signature_algorithm` on `Block` and `DagBlock` for dual-signing migration
- `HashAlgorithm` enum (`Sha256`, `Sha3_256`) with `HASH_ALGORITHM` env var, configurable `hash()` / `hash_with()`, KAT self-tests at startup
- `SigningAlgorithm::is_post_quantum()` helper, `Default` impl (Ed25519 for backwards compat)
- All new fields use `#[serde(default)]` for backwards compatibility with legacy JSON

PQC enforcement:
- `REQUIRE_PQC_SIGNATURES=true` env var rejects Ed25519 in consensus and endorsement validation
- `validate_signature_consistency()` catches tag forgery (declared algorithm vs actual signature size)
- Integrated into `ConsensusEngine::accept_block()` and `validate_endorsements()`

TLS post-quantum handshake:
- `rustls-post-quantum` dependency: X25519+ML-KEM-768 hybrid key exchange
- `TLS_PQC_KEM=true` env var installs PQ `CryptoProvider` at startup
- `install_crypto_provider()` called before any TLS config is built

Dual-signing for migration:
- `dual_sign()` and `verify_dual()` with `Either` / `Both` modes
- `DUAL_SIGN_VERIFY_MODE` env var for transition policy

Equivocation detection:
- `EquivocationDetector` with `ConsensusPosition` key `(height, slot, proposer)`
- `EquivocationProof` with two block hashes + two signatures + algorithm tag
- Gossip deduplication, `receive_proof()`, `is_penalized()` quarantine
- Serde persistence (`to_bytes()` / `from_bytes()`) for restart survival

Slashing economics:
- `PenaltyManager` with `PenaltyRecord`, `PenaltyPolicy`, `PenaltyStatus` (Active/Expired/Permanent)
- Deterministic expiration at `start_height + duration`, permanent mode, escalation on repeat
- Anti-double-slash via `processed_proofs` set, reputation tracking
- Serde persistence for restart survival

New modules:
- `src/crypto/hasher.rs` — configurable SHA-256 / SHA3-256 hash abstraction
- `src/identity/pqc_policy.rs` — PQC enforcement + signature consistency validation
- `src/identity/dual_signing.rs` — dual-signing helpers for crypto migration
- `src/consensus/equivocation.rs` — equivocation detection, proofs, gossip, persistence
- `src/consensus/slashing.rs` — penalty lifecycle, policy, reputation, persistence

New test suites:
- `tests/pqc_security_audit.rs` — 24 adversarial tests (tag forgery, downgrade, dual-sign bypass, TLS, hash migration)
- `tests/chaos_network.rs` — 11 multi-node scenarios (partition, replay, crash, mixed config, flood, convergence)
- `tests/persistent_crash_recovery.rs` — 5 RocksDB crash/restart tests (exact state restoration, tampered storage rejection)
- `tests/crypto_dos_flood.rs` — 6 flood resistance tests (10K invalid flood, duplicate caching, rate limiting, cheap rejection ordering)
- `tests/byzantine_equivocation.rs` — 9 equivocation tests (detection, proof, gossip dedup, penalty, negative cases, stress)
- `tests/equivocation_persistence_partition.rs` — 6 tests (penalty restart survival, cross-partition retroactive detection)
- `tests/slashing_penalty_lifecycle.rs` — 9 tests (active/expired/permanent penalties, restart, escalation, anti-double-slash)
- `tests/performance_guardrails.rs` — 6 threshold tests (cheap rejection 213x faster, 4843 blocks/sec PQC validation, RocksDB 10K reopen 641ms)
- `benches/pqc_performance.rs` — 9 Criterion benchmarks (ML-DSA sign/verify, SHA3, block validation, RocksDB, flood rejection, throughput)

Dependencies: `sha3 = "0.10"`, `rustls-post-quantum = "0.2"`

New env vars: `REQUIRE_PQC_SIGNATURES`, `TLS_PQC_KEM`, `DUAL_SIGN_VERIFY_MODE`, `HASH_ALGORITHM`

Tests: 1503 total (1427 lib + 76 integration), 0 failures

### 2026-04-25

**PIN Module — Generation, Hashing, and DID Association**
- `src/pin/generator.rs` — CSPRNG numeric PIN generator (4-6 digits), Argon2id hashing, verification
- `src/pin/store.rs` — `PinStore` trait with `MemoryPinStore` (DID-to-hashed-PIN mapping)
- `src/api/handlers/pin.rs` — `POST /pin/generate` (generate + hash + associate to DID), `POST /pin/verify` (verify PIN against stored hash)
- `AppState.pin_store` initialized with `MemoryPinStore` at startup
- Dependency: `argon2 = "0.5"`
- 16 unit tests (10 generator + 6 store)

### 2026-04-24

**Cerulean Voto — Electronic voting frontend MVP**
- `cerulean-voto/` — standalone Vite + React + Tailwind app for blockchain-backed elections
- Same stack and patterns as `block-explorer-vite/` (lazy routes, axios unwrap, Tailwind theme, PageIntro)
- Landing page with hero, 3 pillars (immutable, verifiable, post-quantum), dual CTAs
- Dashboard: active/closed election stats, tally bars, navigation to vote
- Elections: create elections via governance API, full history table
- Vote: voter identity (DID + stake), Yes/No/Abstain buttons, live tally bars
- Results: public audit view with percentage bars, quorum/pass indicators
- Voters: register voters via identity API (DID), lookup by DID
- Proxies `/api` to node on port 5174 (independent from block explorer)

**Documentation — E-voting quotation**
- `docs/COTIZACION-VOTO-ELECTRONICO.md` — formal quotation for e-voting system over Cerulean Ledger
- `docs/COTIZACION-VOTO-ELECTRONICO.html` — styled HTML version for PDF export
- `docs/COTIZACION-VOTO-ELECTRONICO.pdf` — print-ready PDF

**Documentation — Presentation materials (Blockchain Chamber Chile)**
- `docs/DEMO-SCRIPT.md` — 5-minute live demo script with timing, commands, checklist, and fallback plan
- `docs/TESSERACT.md` — standalone doc: 4D probability field, 4 physics laws, comparisons, relevance for the Chamber
- `docs/ONE-PAGER-CAMARA.md` — rebranded from "rust-bc" to "Cerulean Ledger", updated year and license
- `docs/PUBLIC-ROADMAP.md` — rebranded, added concrete dates (Q2-Q4 2026, H1-H2 2027), new deliverables and success metrics

**PDF dossier — technical (all-in-one deliverable)**
- `docs/DOSSIER-CAMARA-BLOCKCHAIN-CHILE.pdf` — 44-page consolidated PDF with cover, TOC, and navigable bookmarks
- Individual PDFs for all 7 presentation documents (pandoc + weasyprint)

**Documentation — Commercial dossier (non-technical)**
- `docs/RESUMEN-NO-TECNICO.md` — plain-language overview: what it is, what it solves, for whom
- `docs/QUE-ES-DLT-EMPRESARIAL.md` — DLT concepts, why Rust, FIPS 204, PQC end-to-end, standards (NIST/CNSS/eIDAS/CMF/SII), Fabric comparison
- `docs/CASOS-PRACTICOS.md` — 6 business cases with before/after tables (agro, HR, finance, gov, health, supply chain)
- `docs/POR-QUE-CERULEAN.md` — 5 reasons, value comparison, adoption path, commercial FAQ
- `docs/DOSSIER-COMERCIAL.pdf` — 30-page consolidated PDF with cover, TOC, and navigable bookmarks
- `docs/PRESENTACION.md` — fixed code block overflow in EOV diagram

### 2026-04-23

**Block Explorer — Tesseract page**
- `Tesseract.tsx` — standalone `/tesseract` route explaining the geometric consensus prototype
- Four interactive tabs: Conceptos, Leyes fisicas, Comparativa, Demo
- `FieldDemo.tsx` — interactive 10x10 probability field simulation (seed, crystallize, destroy, self-heal, fake injection)
- "En simples palabras" right-side drawer with accessible analogies
- Bidirectional navigation: Landing ↔ Tesseract via CTA buttons
- Dynamic document title per route, favicon removed

**Governance — HTTP API + Explorer UI**
- `src/api/handlers/governance.rs` — 7 REST endpoints: protocol params, proposal CRUD, voting, tally
- `AppState` fields: `proposal_store`, `vote_store`, `param_registry` initialized at startup
- Routes registered under `/api/v1/governance/`
- `Governance.tsx` — proposals, stake-weighted voting with visual tally bar, protocol parameters table
- 10 governable parameters exposed (block size, fees, quorum, thresholds, etc.)

**Block Explorer — Services routing + Landing refinement**
- `ServicesLayout.tsx` — dedicated layout with compact sidebar listing all services, sticky sidebar (no scroll bleed)
- All service pages mounted under `/services/*` with consistent header and navigation
- `Services.tsx` — card grid (10 services, SVG icons, compact 5-column layout)
- Landing: "Ver servicios" button navigates to `/services`
- `Layout.tsx` — added "Gobernanza" nav group in sidebar
- API client: 7 governance functions + 4 types (Proposal, Vote, TallyResult, ProtocolParam)

**Documentation — Presentation materials for Blockchain Chamber Chile**
- `docs/PRESENTACION.md` — full platform overview tailored for board presentation
- `docs/FAQ.md` — ~40 questions organized by audience (board, enterprise, technical, regulators)
- `docs/PITCH.md` — talking points, one-liners per audience, objection handling, demo flow
- `docs/PQC-TEST-EVIDENCE.md` — concrete PQC test inventory (12 dedicated + 250+ integration)

### 2026-04-17

**Block Explorer — New pages and cleanup**
- Removed legacy Next.js block explorer (`block-explorer/`)
- Added 6 new pages to Vite explorer: Wallets, Transactions, Mining, Staking, Channels, Governance
- New API client functions: `getWallets`, `stakeTokens`, `requestUnstake`, `listChannels`, `createChannel`, `getChannelConfig`
- Updated nav layout with 11 sections (was 6)
- Wallets: list + create wallet
- Transactions: send transactions + live mempool view
- Mining: mine blocks with existing or new wallet
- Staking: stake/unstake tokens + validator table with actions
- Channels: create Fabric-style channels + view config
- Governance: informational page (API endpoints pending backend exposure)
- Demo RRHH: guided 5-step credential verification flow (register issuer → register candidate → issue credential → verify → full profile), highlighted nav button, verification time display
- Wallets page: removed dependency on non-existent `GET /wallets` endpoint; now uses session-based wallet list with lookup by address
- Fixed Vite proxy: `.env` default changed to `http://127.0.0.1:8080` for local development
- Redesigned Layout: flat nav replaced with categorized sidebar (Demos, Red, Tokens, Identidad, Smart Contracts) with descriptions per item, responsive hamburger menu
- Redesigned Home: hub with grouped cards explaining each capability, replaced flat block list

**Documentation**
- `docs/HR-DOCUMENT-VERIFICATION-IMPACT.md` — Impact analysis: blockchain-based document verification for HR hiring processes (DIDs, verifiable credentials, channel privacy, PQC signatures)
- Moved root-level docs to `docs/`: `PUBLIC-ROADMAP.md`, `BENCHMARKS-RESULTS.md`, `HOKTUS-BLOCKCHAIN-IMPACT.md`, `ONE-PAGER-CAMARA.md`
- Cleaned up stale root-level files: `FABRIC-GAP-ANALYSIS.md`, `MULTI-PEER-ENDORSEMENT.md`, `ROADMAP.md`
- Removed tracked Python `__pycache__` files from `sdk-python/`

### 2026-04-16

**Consensus — BFT (Phases 1–3)**
- `consensus::bft::types` — `VoteMessage`, `QuorumCertificate`, `BftPhase` (Prepare→PreCommit→Commit→Decide), phase-aware signing payload for domain separation
- `consensus::bft::quorum` — `QuorumValidator` (2f+1 threshold), `SignatureVerifier` trait, `ensure_bft_viable()` guard (min 4 validators)
- `consensus::bft::vote_collector` — accumulates votes per (phase, round, hash), signals quorum
- `consensus::bft::round` — event-driven state machine per round: AwaitingProposal→Preparing→PreCommitting→Committing→Decided/Failed
- `consensus::bft::round_manager` — orchestrates rounds with round-robin leader rotation, exponential backoff timeouts (3s–30s), highest QC tracking
- `DagBlock.commit_qc` — optional `QuorumCertificate` field for BFT-decided blocks
- `ConsensusEngine.with_bft()` — BFT mode validates CommitQC on non-genesis blocks (phase, hash match, quorum)
- 76 BFT unit tests, 143 total consensus tests

**Consensus — Wire protocol & backend abstraction (Phase 4)**
- `consensus::backend` — `ConsensusBackend` trait (Raft/BFT selection), `ConsensusMode` enum, `CONSENSUS_MODE` env var
- P2P `Message` enum: `BftProposal`, `BftVote`, `BftQuorumCertificate`, `BftViewChange` variants
- 147 total consensus tests

**Consensus — Adversarial E2E tests**
- `tests/bft_e2e.rs` — 16 integration tests simulating multi-node BFT networks
- Scenarios: happy path (4/7/10 nodes), equivocation attacks, crash faults, silent leaders with view change, network partitions (minority/majority), partition healing, alternating partitions, 100-round stress tests, mixed faults across rounds
- Safety assertion: no two honest nodes decide different blocks for the same round
- Liveness assertion: progress with up to f Byzantine faults, stall below threshold

**Parallel Transaction Execution (Phase 2)**
- `transaction::parallel` — conflict detector (RAW/WAW/WAR), dependency graph, wave scheduler with longest-path topological sort
- `transaction::executor` — wave-parallel block executor: MVCC validate + apply writes per wave, deterministic ordering within waves, legacy format adapter
- `Gateway.commit_block_parallel()` — batch commit integrating ordering, parallel execution, block persistence, and event emission; returns `BatchTxResult` with parallelism metrics
- 28 new tests (15 parallel + 9 executor + 4 gateway integration), 30 total gateway tests

**Protocol-Native Tokenomics (Phase 3)**
- `tokenomics::economics` — 100M NOTA supply cap, halving issuance curve (50→25→12...), capped block rewards, 80/20 fee split (burn/proposer), EIP-1559 dynamic base fee, epoch tracking, `process_block()` state machine
- `tokenomics::storage_deposit` — `DepositLedger` for lock/refund lifecycle: proportional to data size, min deposit floor, delta refund on updates, full refund on delete
- 44 new tests (24 economics + 20 storage deposit)

**Cross-Chain Bridge (Phase 4)**
- `bridge::types` — chain registry, message envelope with routing/sequencing, transfer records, inclusion proof structures
- `bridge::escrow` — `EscrowVault` for lock/release (outbound) and mint/burn (inbound) with multi-chain wrapped token balances
- `bridge::verifier` — Merkle tree builder and inclusion proof verification (SHA-256, power-of-two padding, tamper detection)
- `bridge::protocol` — `BridgeEngine` orchestrating chain registry, outbound initiate, inbound verify+mint, replay protection, confirmation threshold checks
- 43 new tests (5 types + 16 escrow + 11 verifier + 11 protocol)

**On-Chain Governance (Phase 5)**
- `governance::params` — typed parameter registry with protocol defaults (block size, fees, slashing, quorum, thresholds)
- `governance::proposals` — proposal lifecycle: submit with deposit → vote → pass/reject → timelock → execute/cancel, with status filtering and ID sequencing
- `governance::voting` — stake-weighted voting (Yes/No/Abstain), quorum check against total staked power, pass threshold on yes/(yes+no), abstain counts for quorum only, full governance integration test
- 34 new tests (7 params + 13 proposals + 14 voting including end-to-end flow)

**Concurrent Execution & Light Client**
- `transaction::executor::execute_block_concurrent()` — async tokio executor: spawns validation tasks per tx within each wave, applies writes deterministically after all validations complete
- `light_client::header` — compact `BlockHeader` (~300 bytes vs ~10 KB full block), `HeaderChain` with hash integrity and parent linkage verification
- `light_client::client` — `LightClient` with BFT header verification (CommitQC validation), state proof verification via Merkle proofs against synced headers, 100-header sync stress test
- 30 new tests (6 concurrent executor + 13 header + 11 client)

**Remaining Gap Closures: DPoS, Bridge E2E, TPS Benchmark**
- `consensus::dpos` — stake-weighted validator selection: committee election (filter, sort, top-N), stake-proportional leader rotation, voting power, 1000-candidate stress test
- `tests/bridge_e2e.rs` — 11 full-lifecycle tests: outbound lock/release, outbound refund, inbound verify/mint, inbound burn/return, multi-chain flows, replay attack, insufficient confirmations, invalid proof, 100-transfer stress (outbound + inbound)
- `tests/tps_benchmark.rs` — 6 throughput benchmarks: independent/contended/mixed workloads, sync vs concurrent parity, measured ~4.5K TPS (debug) for 500 independent txs in 1 wave

**Testnet Infrastructure**
- `testnet::config` — `GenesisConfig` with testnet/devnet/mainnet presets, initial allocations, validator set, DPoS params, validation rules
- `testnet::faucet` — rate-limited token faucet with cooldown, depletion tracking, unlimited mode for devnet
- 18 tests (8 genesis config + 10 faucet)

**EVM Compatibility Layer**
- `evm_compat::abi` — Solidity ABI encoding/decoding (uint256, address, bool, bytes, string), function selectors, DID-to-address derivation
- `evm_compat::precompile` — precompile interface (SHA-256, identity, ecrecover/ripemd160/modexp stubs), gas metering, rust-bc SHA-256 extension at 0x20
- 27 tests (15 ABI + 12 precompile)

**Channel Isolation & Chaincode Upgrade Lifecycle**
- `channel::store` — `ChannelStore` with per-channel world state and block ledger isolation, version independence, key prefixing (Fabric-compatible)
- `chaincode::upgrade` — `UpgradeManager` with multi-org approval lifecycle: propose→approve→commit, progress tracking, unauthorized/duplicate rejection, history
- 24 tests (11 channel store + 13 upgrade lifecycle)

**TPS Benchmark, Bridge Relayer, and Ecosystem Docs**
- `tests/full_benchmark.rs` — release-mode benchmarks: 56K TPS (500 independent), 39K TPS (1000 mixed), 100 BFT rounds/sec, full pipeline (BFT + exec + state)
- `bridge::relayer` — `Relayer` with job queue, batch processing, retry logic, replay protection, status tracking; 7 tests including 100-relay stress
- `docs/book/` — mdBook documentation site: introduction, quickstart, configuration, first dApp guide (Wasm + Python SDK + JS SDK), architecture/API/operations stubs

**Documentation**
- `docs/IOTA-GAP-ANALYSIS.md`: competitive gap analysis vs IOTA Rebased with suggested roadmap

### 2026-04-14

**Node**
- Fix infinite recursion in `Node::p2p_address()` when no announce address is set (fallback is `address`).
- RocksDB open now unions static CFs with `list_cf` on disk so dynamic families (e.g. `private_*` from private data) open without startup errors.

**Tooling**
- `docker-compose.yml`: removed obsolete top-level `version` (Compose v2).
- `scripts/try-it.sh`: local demo without Docker.
- `tests/fuzz_tests.proptest-regressions`: proptest regression seeds.

**Explorer**
- `block-explorer-vite/`: Vite + React UI for the HTTP API; dev server proxies API calls to the node (see `vite.config.ts` / `VITE_API_PROXY_TARGET`). Plain-language flows for identities and credentials.

---

### 2026-04-13 (Debug build stack overflow fix)

- `async_main` refactored into `async_main` + `async_main_inner` with `Box::pin` indirection
- The 1200-line async state machine now lives on the heap instead of the thread stack
- Fixes stack overflow that prevented `cargo run` (debug mode) from starting
- Stack size reduced from 64 MB back to 16 MB (sufficient with heap-allocated future)
- Release mode was unaffected (optimizations already collapsed the state machine)

### 2026-04-13 (E2E test suite compatibility fixes)

- Force HTTP/1.1 in e2e script to avoid HTTP/2 negotiation failures with rustls
- Prefer Homebrew curl (OpenSSL) over macOS system curl (LibreSSL) to fix `bad_record_mac` on POST requests
- E2E result: 104 passed, 0 failed across 26 categories

---

### 2026-04-12 (Security Hardening — P0/P1/P2)

**P0 — ACL enforcement on legacy routes**
- All 12 mutation endpoints in `api_legacy.rs` now call `enforce_acl` (mine, deploy, execute, connect, sync, stake, unstake, airdrop, wallet, nft metadata)
- `mine_block` verifies `miner_address` belongs to a registered wallet
- Debug `eprintln!("[DEPLOY]...")` replaced with `log::debug!`

**P1 — Double-spend and replay prevention**
- `is_double_spend` rewritten: matches by `tx.id` uniqueness across confirmed chain
- New `validate_timestamp` rejects transactions >30s in the future or >10min old
- Rate limiter: `/billing/create-key` no longer exempt; middleware logging via `log::debug!`
- Removed blanket `#![allow(dead_code)]` from `transaction_validation.rs`; per-item allows only

**P2 — Integrity and supply-chain hardening**
- Checkpoint files now include HMAC-SHA256 tag (env `CHECKPOINT_HMAC_SECRET`); tampered/legacy files skipped on load
- Chaincode install computes and logs SHA-256 of Wasm bytes; optional `expected_hash` query param for verification
- `jwt_secret` documented as reserved (not used for auth — mTLS + ACL is active)

**Tests:** 992 passed, 0 failed, 0 clippy warnings

---

### 2026-04-12 (Chaincode Install Fix)

- Input validation middleware now exempts `/chaincode/install` from the JSON-only Content-Type check, allowing `application/octet-stream` for Wasm binary uploads
- E2E test suite: 69 passed, 0 failed (previously 62 passed, 4 failed on chaincode lifecycle)

---

### 2026-04-11 (Audit Hardening)

**Wasmtime upgrade (v21 → v36)**
- Resolves 15 CVEs including sandbox escape, memory leaks, and host panics
- Rust toolchain updated to `nightly-2025-05-01` (1.88.0) for compatibility
- Removed `#![feature(unsigned_is_multiple_of)]` (stable since 1.87)

**Clippy clean pass**
- Zero warnings from `cargo clippy -- -D warnings`
- 199 `uninlined_format_args` auto-fixed for Rust 1.88 lint rules
- Removed crate-level `#![allow(dead_code, unused_imports)]` from `lib.rs` and `main.rs`
- 144 previously hidden warnings resolved: unused imports removed, dead code annotated per-item
- Removed file-level `#![allow(dead_code)]` from `chain_validation.rs`, `transaction_validation.rs`, `network_security.rs`

**Dependency CVE fix**
- `bytes` 1.11.0 → 1.11.1 (RUSTSEC-2026-0007, integer overflow in `BytesMut::reserve`)

---

### 2026-04-10 (Production Readiness — Final Gaps)

**3-node Raft ordering cluster**
- Docker Compose default changed from solo to 3-node Raft (`ORDERING_BACKEND=raft`)
- Orderer1/2/3 with `RAFT_NODE_ID` and `RAFT_PEERS` configured for automatic cluster formation
- Persistent Raft log per orderer (RocksDB at `STORAGE_PATH/raft/`)
- TLS certificates generated for all 3 orderers via `deploy/generate-tls.sh`

**Performance benchmarks published**
- `docs/BENCHMARKS-FULL.md` with Criterion measurements on Apple M-series
- Ordering: 23M tx/s (in-memory), endorsement: 45K/s (Ed25519), RocksDB: 104K blocks/s
- End-to-end pipeline estimate: 5K-15K tx/s on 3-node Raft LAN
- Comparison table with Hyperledger Fabric published TPS

**Chaincode SDK for Rust developers**
- `chaincode-sdk/` — Rust crate that compiles to Wasm for deployment on the blockchain
- API: `state_put`, `state_get`, `state_put_json`, `state_get_json`, `emit_event`, `set_key_policy`, `history_for_key`, `invoke` (cross-chaincode), `set_response`
- Example: `examples/asset_transfer.rs` — complete asset management contract (create, read, transfer, history)
- Compiles to `wasm32-unknown-unknown` target

---

### 2026-04-10 (Certification Readiness — Levels 1-3)

**Level 1 — Enterprise presentation readiness**
- MIT license added
- `JWT_SECRET` required in production (`RUST_BC_ENV=production` panics if missing or default)
- Signing key zeroization: Ed25519 via `ZeroizeOnDrop`, ML-DSA-65 via custom `Drop`
- Integration test fixed for PQC signature migration (`store_blocks_api_test.rs`)

**Level 2 — Third-party audit readiness**
- Property-based tests (proptest): 5 cases for Ed25519 + ML-DSA-65 sign/verify invariants
- Input validation middleware: Content-Type enforcement, max payload size (10 MB), wired at startup
- Vulnerability disclosure policy added to SECURITY.md (72h ack, 7-day fix timeline)
- Consensus threat model added to SECURITY.md (Raft, gossip, censorship attacks + mitigations)
- CI coverage gate: `cargo tarpaulin --fail-under 80`, test steps no longer soft-fail
- Production unwrap audit: single handler unwrap fixed in events.rs
- `docs/ENCRYPTION-AT-REST.md` — LUKS, Docker, cloud encryption guidance

**Level 3 — Formal certification preparation**
- FIPS 140-3 power-up self-tests (KAT): Ed25519, ML-DSA-65, SHA-256 run at startup; node refuses to start on failure
- `docs/FIPS-140-MODULE.md` — cryptographic module boundary, approved algorithms, key management, gap analysis
- `docs/COMPLIANCE-FRAMEWORK.md` — SOC 2 (13 criteria), ISO 27001 (17 Annex A controls), regulatory mapping (Chile CMF, EU eIDAS/GDPR, US FISMA)
- `docs/CERTIFICATION-ROADMAP.md` — three-level roadmap with items, effort, and audience per level

**Dependencies:** `zeroize` 1.7, `proptest` 1.4 (dev)

---

### 2026-04-10 (Fabric Parity Audit + Enterprise Documentation)

**Structural audit against Hyperledger Fabric**
- Verified full Fabric feature parity across 6 critical areas
- Channel ledger isolation confirmed: `StoreMap` (per-channel `HashMap<String, Arc<dyn BlockStore>>`) used by all store handlers via `channel_id_from_req()` + `get_channel_store()`
- Private data dissemination confirmed: selective push to member peers via discovery service, membership validation on receive, `PrivateDataAck` responses
- Chaincode lifecycle confirmed: `Installed → Approved → Committed` state machine with per-org approval tracking and endorsement policy evaluation on commit
- Pull state sync confirmed: `StateRequest`/`StateResponse` messages, anti-entropy gap detection via alive message heights
- WebSocket events confirmed: `actix-ws` upgrade, `EventBus` subscription, channel/chaincode filtering, historical replay, client ack tracking

**Fix: proposals handler channel scoping**
- `POST /api/v1/proposals` now persists transactions to the channel-scoped store (was hardcoded to `"default"`)

**Enterprise documentation**
- `docs/ENTERPRISE.md` — Platform overview for enterprise evaluation (architecture, privacy, consensus, chaincode, endorsement policies, PQC, operations, use cases, Fabric comparison)
- `docs/PQC-ENTERPRISE.md` — Post-quantum cryptography positioning document for the Chamber (NIST FIPS 204 compliance, Fabric comparison, regulatory alignment, deployment model)

---

### 2026-04-10 (Post-Quantum Cryptography — FIPS 204)

**ML-DSA-65 signing provider**
- `MlDsaSigningProvider` implements `SigningProvider` using ML-DSA-65 (FIPS 204, NIST security level 3)
- Keypair generation, signing (3309-byte signatures), and verification via `pqcrypto-mldsa`
- `from_keys(pk, sk)` constructor for restoring providers from persisted key material

**Generalized `SigningProvider` trait**
- Signatures and public keys changed from fixed-size arrays to `Vec<u8>` / `&[u8]`
- New `algorithm()` method returns `SigningAlgorithm` enum (`Ed25519` or `MlDsa65`)
- `SoftwareSigningProvider` (Ed25519) and `HsmSigningProvider` adapted to the new trait

**Variable-length signatures across the stack**
- `Endorsement.signature`: `[u8; 64]` → `Vec<u8>`
- `Block.signature` and `Block.orderer_signature`: `[u8; 64]` → `Vec<u8>`
- `DagBlock.signature`: `[u8; 64]` → `Vec<u8>`
- `TransactionProposal.creator_signature`: `[u8; 64]` → `Vec<u8>`
- `AliveMessage.signature` (gossip): `[u8; 64]` → `Vec<u8>`
- All hex serde helpers updated for variable-length byte vectors

**Runtime algorithm selection**
- `SIGNING_ALGORITHM` env var: `ed25519` (default), `ml-dsa-65` / `mldsa65`
- Logged at startup; unknown values fall back to Ed25519 with a warning

**Legacy transaction verification**
- `Transaction.verify_signature()` auto-detects Ed25519 or ML-DSA-65 by key/signature size

**Dependencies:** `pqcrypto-mldsa` 0.1.2, `pqcrypto-traits` 0.3

---

### 2026-04-07 (Fabric Gap Closure)

**Persistent Raft log (crash-tolerant ordering)**
- `RocksDbRaftStorage` implements `raft::Storage` trait with RocksDB
- Entries, HardState, ConfState, and Snapshots persist to `{STORAGE_PATH}/raft/`
- `RaftNode::new_persistent()` loads state from disk on boot, flushes after each advance
- Each Docker orderer is an independent process with its own persistent Raft DB
- Process crash + restart recovers full Raft state and re-integrates to cluster

**X.509 MSP enforcement**
- `TlsIdentityMiddleware` extracts CN/O from mTLS client certificates via `x509-parser`
- `on_connect` captures DER peer certs from rustls `ServerConnection`
- `enforce_acl` uses TLS identity as authoritative source, headers as fallback
- Role inference from CN: "admin" → Admin, "peer"/"orderer" → Peer, else → Client

---

### 2026-04-07 (Post-MVP — Block 3)

**External chaincode (chaincode-as-a-service)**
- `ChaincodeDefinition.runtime` field: `Wasm` (default) or `External { endpoint, tls }`
- Simulate handler dispatches to `ExternalChaincodeClient` for external runtime
- HTTP POST to `{endpoint}/invoke` with JSON body

**TLS Identity Middleware**
- `TlsIdentityMiddleware` extracts CN/O from `X-TLS-Client-CN`/`X-TLS-Client-O` headers
- Inserts `TlsIdentity` into request extensions for downstream handlers
- Compatible with TLS-terminating proxies

**HSM signing (feature-gated)**
- `#[cfg(feature = "hsm")]` sign/verify paths on `HsmSigningProvider`
- Verify uses `ed25519_dalek` with cached public key
- Sign path documented for PKCS#11 `C_Sign` (requires hardware testing)

**Already complete (preexisting)**
- Hot certificate rotation — SIGHUP + periodic reload already implemented
- Block explorer UI — Next.js app in `block-explorer/`
- CouchDB world state — `WorldState` trait fully implemented in `storage/couchdb.rs`

---

### 2026-04-07 (MVP Readiness)

**Graceful shutdown**
- SIGTERM/SIGINT handler via `tokio::signal` — drains HTTP connections, aborts background tasks, flushes RocksDB

**Persistent service stores**
- 8 of 9 services now persist to RocksDB when `STORAGE_BACKEND=rocksdb`
- New CF impls: `PolicyStore`, `CollectionRegistry`, `ChaincodeDefinitionStore`
- Added serde derives to `PrivateDataCollection`, `ChaincodeDefinition`, `ChaincodeStatus`
- Single shared `Arc<RocksDbBlockStore>` instance for all services
- Explicit failure: node exits if `STORAGE_BACKEND=rocksdb` and DB fails to open (no silent fallback)

**Health check with dependency verification**
- `/api/v1/health` now reports `checks: { storage, peers, ordering }`
- Returns `"degraded"` when storage or ordering is unavailable

**JS/TS SDK — Fabric-style operations**
- New methods: `submitTransaction`, `evaluate`, `registerOrg`, `setPolicy`, `createChannel`, `listChannels`, `putPrivateData`, `getPrivateData`

**Mutex poison recovery**
- Replaced 178 `.lock()/.read()/.write().unwrap()` with `unwrap_or_else(|e| e.into_inner())`
- Prevents cascading panics across threads from poisoned locks

**Documentation**
- `docs/QUICK-START.md` — git clone to first transaction in < 5 minutes
- `docs/API-REFERENCE.md` — all 68 endpoints with curl examples
- `docs/DEPLOYMENT.md` — production config, env vars, security checklist
- `docs/MVP-ROADMAP.md` — task-level breakdown for MVP delivery

---

### 2026-04-07 (CI Stabilization)

**Docker TLS permissions**
- `deploy/generate-tls.sh` now runs `chmod 644` on generated `.pem` files so the non-root container user (`rustbc`, uid 1000) can read them through the read-only `/tls` volume mount

**E2E test resilience**
- Grafana health check skipped when Grafana is not running (CI only starts blockchain nodes)
- Channel membership test asserts "not 403" instead of exact 200, isolating membership enforcement from downstream endorsement errors
- `POST /api/v1/store/transactions` now returns `status_code: 201` in the JSON envelope to match the HTTP 201 Created status

**Flaky Raft test fix**
- `three_nodes_in_process_propose_committed_on_all` routing rounds increased from 30 to 50, accommodating worst-case Raft election timeout randomisation on slow CI runners

**CI status:** all 4 jobs green (Check + Clippy, Build CLI, Unit Tests, E2E Tests)

---

### 2026-04-07 (Production Hardening)

**ACL deny-by-default**
- `enforce_acl()` now denies requests with missing identity, missing ACL infrastructure, or undefined ACL entries
- New env var `ACL_MODE=permissive` restores the old allow-all behavior for local development
- `enforce_channel_membership()` denies requests without `X-Org-Id` on non-default channels (strict mode)

**JWT secret from environment**
- `ApiConfig` reads `JWT_SECRET` env var at startup; falls back to hardcoded default only if unset

**CouchDB async client**
- Replaced `reqwest::blocking::Client` with async `reqwest::Client` in `CouchDbWorldState`
- Sync `WorldState` trait bridged via `block_in_place` + `Handle::block_on` (no runtime deadlock)
- Same fix applied to `ExternalInvoker` in `src/chaincode/invoker.rs`

**Configurable P2P buffer sizes**
- `P2P_RESPONSE_BUFFER_BYTES` — `send_and_wait` responses (default 256 KB, was 64 KB)
- `P2P_HANDLER_BUFFER_BYTES` — per-connection message handler (default 64 KB, was 8 KB)
- `P2P_SYNC_BUFFER_BYTES` — pull-based state sync responses (default 4 MB, was 1 MB)

---

### 2026-04-06 (E2E Tests, Operator Tooling, Full Service Wiring & Gap Analysis)

**All scaffold services wired to startup**
- `org_registry`, `policy_store`, `discovery_service`, `private_data_store`, `collection_registry`, `chaincode_package_store`, `chaincode_definition_store`, `gateway` initialized in `main.rs`
- `POST /api/v1/private-data/collections` endpoint added for collection registration

**Route registration fix**
- `ApiRoutes::register()` uses `.configure()` closures to break the generic type chain and prevent stack overflow from deeply nested Actix wrappers
- `ApiRoutes::configure()` kept for integration tests, `configure_metrics()` for production
- Main thread spawned with 32 MB stack to accommodate release + debug builds

**E2E test suite** (`scripts/e2e-test.sh`) — 42 pass, 0 fail, 0 skip
- Organizations, endorsement policies, channel isolation
- Block mining with multi-node propagation
- Transaction lifecycle (wallet → mempool → mine → block)
- Private data (register collection → write → read authorized → deny unauthorized)
- Discovery (register peers → query endorsers → query channel peers)
- Gateway (endorse → order → commit pipeline)
- Chain integrity, Prometheus metrics, Grafana health
- Store CRUD (identities, credentials)

**Operator CLI** (`scripts/bcctl.sh`)
- 14 commands: `status`, `peers`, `blocks`, `mine`, `wallet create`, `channels`, `channel create`, `orgs`, `logs`, `restart`, `metrics`, `verify`, `consistency`, `env`

**Fabric 2.5 gap analysis** (`FABRIC-GAP-ANALYSIS.md`)
- Detailed comparison: 12 verified E2E categories, 10 implemented-but-untested features, gaps vs Fabric
- Research-backed task backlog with code change requirements, blockers, and exact E2E steps
- Key findings: Raft is in-process only (no network transport), MVCC not wired to gateway, install doesn't create chaincode definition, world_state not initialized for snapshots

---

### 2026-04-05 (Docker & P2P Networking)

**Docker deployment**
- Multi-stage `Dockerfile` (nightly Rust builder + `debian:bookworm-slim` runtime)
- `docker-compose.yml`: 3 peers + 1 orderer + Prometheus + Grafana
- Self-signed TLS via `deploy/generate-tls.sh` (EC P-256, per-node SANs)
- Non-root container user, named volumes for persistence

**Network fixes for containerized nodes**
- `BIND_ADDR` env var for HTTP listen address (default `127.0.0.1`, containers use `0.0.0.0`)
- `P2P_EXTERNAL_ADDRESS` env var for announce address (e.g. `node1:8081`)
- `Node::p2p_address()` helper replaces 8 hardcoded `self.address` formats
- P2P TLS acceptor now configured on the server node (was missing)
- Fixed `TLS_CA_CERT_PATH` env var name in compose (was `TLS_CA_PATH`)

**Route unification**
- Merged legacy and scaffold into a single `/api/v1` scope
- `ApiRoutes::register()` appends scaffold sub-services into the legacy scope
- `ApiRoutes::configure()` retained for integration tests (standalone scope)
- `ApiRoutes::configure_metrics()` used in production (metrics only)
- `health`, `version`, `openapi.json` registered as `.route()` in the legacy scope

**E2E verified**
- 4 nodes healthy, 3 peers each via mutual TLS
- Block mining on node1 propagates to node2/node3 within seconds
- 2020 unit/integration tests passing

---

### 2026-04-04 (Fase 19 — Snapshots + Pagination)

**19.1 — State snapshots**
- `StateSnapshot` metadata struct in `src/storage/snapshot.rs`
- `create_snapshot()`: serializes world state to `{key}\t{version}\t{base64}\n` format with SHA-256 hash
- `restore_snapshot()`: reads `.snap` file, restores world state, verifies hash integrity
- API handlers: `POST /snapshots/{channel_id}`, `GET /snapshots/{channel_id}`, `GET /snapshots/{channel_id}/{id}`
- `AppState.world_state` field added; `base64 = "0.22"` dependency added

**19.2 — State regeneration**
- `regenerate_state()`: replays all blocks from store to rebuild world state

**19.3 — Pagination**
- `PaginationParams` (page/limit/cursor) and `PaginatedResponse<T>` in `src/api/pagination.rs`
- `BlockStore::list_blocks(offset, limit)` with default implementation
- `GET /store/blocks` now accepts `?page=N&limit=M` and returns `PaginatedResponse`

---

### 2026-04-04 (Fase 18 — Delivery Service)

**18.1 — DeliverFiltered**
- `FilteredBlock` and `FilteredTx` structs in `src/events/filtered.rs`
- `to_filtered_block()` strips payload/rwset/endorsements, keeps only tx IDs and validation codes
- `GET /events/blocks/filtered` WebSocket streams `FilteredBlock` summaries

**18.2 — DeliverWithPrivateData**
- `BlockWithPrivateData` struct in `src/events/private_delivery.rs`
- `GET /events/blocks/private` WebSocket with `X-Org-Id` header for collection membership filtering
- `CollectionRegistry::list()` method added for iterating registered collections

**18.3 — Replay and checkpoints**
- `start_block` field in `WsFilter`: replays historical blocks before switching to live
- `ack` + `client_id` checkpoint system: server tracks last acked height per client
- Reconnect with same `client_id` resumes from `last_ack + 1`

---

### 2026-04-04 (Fase 17 — Key History + Chaincode-to-Chaincode)

**17.1 — Key history**
- `HistoryEntry` struct in `storage/traits.rs`
- CF `key_history` in RocksDB with `{key}\x00{version:012}` key schema
- `get_history` method on `WorldState` trait, implemented for Memory and RocksDB
- `put()` and `delete()` auto-append history entries in `MemoryWorldState`
- `get_history_for_key` host function in `WasmExecutor`

**17.2 — Chaincode-to-chaincode invocation**
- `ChaincodeResolver` trait + `StoreBackedResolver` in `src/chaincode/resolver.rs`
- `invoke_chaincode` host function: resolves target, creates child executor, shares `WorldState`
- ACL check via `AclProvider` before cross-chaincode calls (`chaincode/{id}/invoke`)
- `MAX_CHAINCODE_DEPTH=8` recursion limit with depth counter propagation
- `ChaincodeError::NotFound` variant added

---

### 2026-04-04 (Fase 16 — Gossip Protocol Enhancement)

**16.1 — Alive messages**
- `AliveMessage` struct in `src/network/gossip.rs` with Ed25519 signature verification
- `Alive(AliveMessage)` variant in the P2P `Message` enum
- `MembershipTable`: thread-safe peer liveness tracking with suspect sweep
- `start_alive_loop` on `Node`: periodic broadcast + suspect detection
- Refactored `src/network.rs` → `src/network/mod.rs` + `gossip.rs` module

**16.2 — Pull-based state sync**
- `StateRequest { from_height }` and `StateResponse { blocks }` message variants
- `STATE_BATCH_SIZE` (50) caps response payload
- `start_pull_sync_loop` on `Node`: periodic height comparison + block fetch
- Anti-entropy: `latest_height` field on `AliveMessage`, `peers_ahead_of` gap detection

**16.3 — Anchor peers**
- `AnchorPeer` struct with `parse_anchor_peers` from `ANCHOR_PEERS` env var
- `connect_to_anchor_peers` runs before bootstrap for cross-org discovery
- `anchor_peers_from_config` bridges `ChannelConfig.anchor_peers` map to gossip

**16.4 — Leader election per org**
- `LeaderElectionMode` enum (`Static` / `Dynamic`) from `LEADER_ELECTION` env var
- `elect_leader(org_id)`: smallest alive peer address wins; failover on suspect

39 network tests passing.

---

### 2026-04-04 (Fase 15 — Raft Consensus Ordering)

**15.1 — Raft core**
- `RaftNode` in `src/ordering/raft_node.rs`: wrapper over tikv `RawNode<MemStorage>`
- `new`, `tick`, `propose`, `step`, `advance` methods
- Full raft 0.7 ready cycle: handles `messages()` (leader) and `persisted_messages()` (candidate/follower) correctly
- `create_snapshot` / `apply_snapshot` for node catch-up
- 8 tests: init, election, 3-node leader election, propose+commit, 5-entry replication, snapshot transfer

**15.2 — Raft ordering service**
- `RaftOrderingService` in `src/ordering/raft_service.rs`: JSON-serialized TX proposals through raft, committed entry draining with no-op filtering
- `OrderingBackend` trait in `src/ordering/mod.rs` with `submit_tx`, `cut_block`, `pending_count`
- Implemented by both `OrderingService` (solo) and `RaftOrderingService` (raft)
- Backend selection via `ORDERING_BACKEND=raft|solo` env var; `RAFT_NODE_ID`, `RAFT_PEERS` for raft config
- `AppState.ordering_backend: Option<Arc<dyn OrderingBackend>>` added
- 6 tests: 3 raft service + 2 trait object + 1 batch size

**15.3 — Raft network transport**
- `Message::RaftMessage(Vec<u8>)` variant added to P2P `Message` enum
- `src/ordering/raft_transport.rs`: prost encode/decode, `tick_and_collect`, `deliver_raw`
- `prost` dependency aligned to 0.11 (matches raft-proto)
- 3 tests: serde roundtrip, encode/decode roundtrip, 3-node in-process replication through serialized bytes

**15.4 — Orderer block signing**
- `Block.orderer_signature: Option<[u8; 64]>` with `#[serde(default, skip_serializing_if)]`
- `sign_block(block, key)`: `sha256(height || parent_hash || merkle_root)` signed with Ed25519
- `verify_orderer_signature(block, verifying_key)`: `Ok(true)` valid, `Ok(false)` absent, `Err` invalid
- Both backends sign when `with_signing_key(key)` is set
- 4 tests: sign+verify, valid accept, invalid reject, absent accept

---

### 2026-04-04 (Fase 12 — Hardening · §12.3 Benchmarks)

**12.3.1–12.3.3 — Criterion benchmarks** (`benches/ordering_throughput.rs`)
- `ordering_service/submit_and_cut/100` — throughput de ordering: 100 TXs → 1 bloque; reporta TXs/s
- `endorsement_validation/validate_endorsements/{1,3,5,10}` — latencia por endorsement Ed25519 con política `AllOf(N)`
- `event_bus_fanout/publish_1_event/{1,5,10,50}` — costo de `publish()` con N suscriptores activos en canal broadcast
- `criterion = "0.5"` añadido a `[dev-dependencies]`; informes HTML en `target/criterion/`

---

### 2026-04-04 (Fase 7 — Private Data Collections · §7.1.3)

**7.1.3 — Purge de datos expirados**
- `put_private_data_at(collection, key, value, written_at_height, blocks_to_live)` añadido al trait `PrivateDataStore` — default no-op delegando a `put_private_data` para backwards compat
- `purge_expired(current_height)` en el trait con default no-op; `MemoryPrivateDataStore` elimina entradas donde `written_at + blocks_to_live <= current_height`
- Entradas sin TTL (`blocks_to_live = 0`) nunca expiran
- 5 tests: expiración exacta en altura 6, sin expirar antes, purge selectivo (corto vs largo TTL), sin-TTL inmortal, `blocks_to_live=0`

---

### 2026-04-03 (Fase 9 — Fabric Gateway)

**9.1.1 — `Gateway` struct**
- `src/gateway/mod.rs`: campos `org_registry`, `policy_store`, `ordering_service`, `store`
- `mod gateway` declarado en `lib.rs` y `main.rs`
- 3 tests: crear con mocks, store vacío, policy store vacío

**9.1.2 — `Gateway::submit`**
- Pipeline: consulta policy → self-endorse → `ordering_service.submit_tx` → `cut_block` → `store.write_block`
- `TxResult { tx_id, block_height }` como tipo de retorno
- `GatewayError`: `PolicyNotSatisfied`, `Ordering`, `Storage`
- 4 tests: sin policy, `AnyOf` satisfecha, policy no satisfecha, alturas secuenciales

**9.1.3 — `POST /api/v1/gateway/submit`**
- Handler `gateway_submit` en `src/api/handlers/gateway.rs`
- Acepta `{ chaincode_id, transaction: { id, input_did, output_recipient, amount } }`
- Devuelve `{ tx_id, block_height }`; 404 si gateway no configurado; 400 si campos vacíos
- `gateway: Option<Arc<Gateway>>` añadido a `AppState`
- 3 tests HTTP: 200 end-to-end, 404 sin gateway, 400 con campos vacíos

**Total tests: 1470**

---

### 2026-04-03 (Fase 8 — Chaincode Lifecycle · §8.3 Wasm execution)

**8.3.4 — Memory limit**
- `WasmExecutor::with_memory_limit(max_bytes)` builder method
- `StoreLimitsBuilder::memory_size` + `store.limiter()` activan el límite por invocación
- Módulo que pide más páginas de las permitidas falla en instanciación → `ChaincodeError::Execution`
- 2 tests: exceder límite → error, dentro del límite → ok

**8.3.3 — Host functions `put_state` / `get_state`**
- `WasmExecutor::invoke(state, func_name) -> Result<Vec<u8>>`
- ABI: la función Wasm devuelve `i64 = (ptr << 32 | len)`; el host lee `memory[ptr..ptr+len]`
- Imports `env::put_state` y `env::get_state` enlazan la memoria Wasm con `WorldState`
- 2 tests: put→get devuelve `"1"`, estado persistido en `WorldState`

**8.3.2 — `WasmExecutor`**
- `src/chaincode/executor.rs`: `WasmExecutor { engine, module, fuel_limit }`
- Constructor compila Wasm con fuel metering (`Config::consume_fuel(true)`)
- `ChaincodeError::Execution(String)` añadido al enum
- 3 tests: wasm válido ok, fuel_limit guardado, wasm inválido → error

**8.3.1 — Dependencia wasmtime**
- `wasmtime = "21"` añadido a `Cargo.toml`

---

### 2026-04-03 (Fase 7 — Private Data Collections)

**7.2.1 — Access control en handlers de private data**
- `CollectionRegistry` trait + `MemoryCollectionRegistry` en `src/private_data/mod.rs`
- `ApiError::Forbidden` → HTTP 403
- `PUT/GET /api/v1/private-data/{collection}/{key}` en `src/api/handlers/private_data.rs`
- Header `X-Org-Id` obligatorio; `check_membership` verifica org en `member_org_ids` de la collection
- `AppState`: campos `private_data_store` y `collection_registry`
- 6 tests nuevos (member → 200, non-member → 403, sin header → 400, clave ausente → 404)

**7.1.2 — RocksDB private data store**
- `PrivateDataStore` trait + `MemoryPrivateDataStore`; impl para `RocksDbBlockStore` con CF `private_{name}` dinámica
- Helper `sha256` para hash on-chain; DB migrada a `DBWithThreadMode<MultiThreaded>`

**7.1.1 — PrivateDataCollection struct**
- `PrivateDataCollection { name, member_org_ids, required_peer_count, blocks_to_live }` + `is_member()`
- `PrivateDataError`: `InvalidCollection`, `AccessDenied`
- 634 lib + 535 integration tests al cierre de 7.2.1

---

### 2026-04-03 (Fase 3 — Transaction Lifecycle)

**Transaction — Fase 3.1: Read-Write Sets**
- `src/transaction/mod.rs` + `rwset.rs`: `KVRead { key, version }`, `KVWrite { key, value }`, `ReadWriteSet { reads, writes }` con `is_empty()`
- Serde derive en los tres tipos; módulo declarado en `lib.rs` y `main.rs`
- 6 tests nuevos; 531 tests en total

---

### 2026-04-03 (Fase 1–2 — Endorsement + Ordering)

**Endorsement (Fase 1) — completa**
- `src/endorsement/`: `Organization`, `OrgRegistry` trait + `MemoryOrgRegistry`, CF `organizations` en RocksDB
- `EndorsementPolicy` (AnyOf / AllOf / NOutOf / And / Or) + `evaluate()`
- `PolicyStore` trait + `MemoryPolicyStore`
- `Endorsement` struct + `verify_endorsement` + `validate_endorsements`
- `Block.endorsements: Vec<Endorsement>` (serde default)
- `ConsensusEngine::with_policy_store()`: valida endorsements antes de insertar en DAG
- REST: `POST/GET /api/v1/store/organizations`, `GET /api/v1/store/organizations/{id}`, `POST/GET /api/v1/store/policies/{resource_id}`
- `AppState`: `org_registry`, `policy_store`

**Ordering (Fase 2) — completa**
- `src/ordering/`: `NodeRole` enum (Peer / Orderer / PeerAndOrderer) + `FromStr` desde `NODE_ROLE` env
- `OrderingService`: cola `VecDeque<Transaction>`, `submit_tx`, `cut_block` con batch drain
- `run_batch_loop`: tokio task lanzada en `main.rs` si el nodo ordena
- `Node.role: NodeRole`; `Message::SubmitTransaction` y `Message::OrderedBlock`
- `process_message`: orderer ingesta TXs; peer persiste `OrderedBlock` directamente en store
- 525 tests al cierre de Fase 2

---

### 2026-04-03 (Storage)

**Storage — secondary index endpoint**
- `GET /api/v1/store/blocks/{height}/transactions` — queries `transactions_by_block_height` via prefix scan on `tx_by_block` CF

**Storage — secondary index `tx_by_block`**
- New `tx_by_block` CF in RocksDB; key schema `{012-padded-height}:{tx_id}` → empty value
- `write_transaction` and `write_batch` write index entry atomically in the same `WriteBatch`
- `BlockStore::transactions_by_block_height(height)` added to trait; delegated in `Arc<T>` blanket impl
- `MemoryStore`: equivalent linear scan over the HashMap
- 9 new tests (key format, empty result, filtering, no height bleed-over, batch indexing); 463 tests total

**Storage — Fase VI: `MemoryStore` + `Arc<T>` blanket impl**
- `Arc<T: BlockStore>` implements `BlockStore` — lets `Arc<MemoryStore>` be used as `Box<dyn BlockStore>`
- `ConsensusEngine::with_store()` persists accepted blocks into the store

**Storage — Fase V: store-backed REST endpoints**
- `POST/GET /api/v1/store/transactions/{tx_id}`
- `POST/GET /api/v1/store/identities/{did}`
- `POST/GET /api/v1/store/credentials/{cred_id}`
- All handlers return 404 when store is not configured

**Storage — Fase IV: RocksDB Column Families**
- 5 CFs: `blocks`, `transactions`, `identities`, `credentials`, `meta`
- `create_missing_column_families(true)` — compatible with new and existing DBs
- Block keys: zero-padded 12-digit decimal for lexicographic = numeric ordering
- 17 tests: per-type roundtrip, CF isolation, reopen with persisted data

**Storage — Fase III: switcheable backend**
- `STORAGE_BACKEND=rocksdb` → `RocksDbBlockStore` at `STORAGE_PATH`; default → `MemoryStore`
- Fallback to `MemoryStore` if RocksDB fails to open

**Storage — Fase II: RocksDB**
- `RocksDbBlockStore`: JSON serialization, atomic `WriteBatch`, `META:latest_height` tracking
- `rocksdb = "0.22"` added to `Cargo.toml`
- 13 unit tests with `tempfile::TempDir`

**Storage — Fase I: MemoryStore + API**
- `MemoryStore`: `BlockStore` backed by `HashMap` + `Mutex`
- `AppState.store: Option<Arc<dyn BlockStore>>`
- `GET /api/v1/store/blocks/{height}` and `/store/blocks/latest`

**Consensus — Fase H: ConsensusEngine**
- `ConsensusEngine`: wraps `Dag`, `ForkChoice`, and `SlotScheduler`
- `accept_block()` validates and inserts; `canonical_tip()` / `canonical_chain()` query state
- `ConsensusError` typed errors via `thiserror`
- 11 tests

**Consensus — Fase G: Fork Resolution**
- `Dag::subtree_weight()`, `canonical_chain()`, `resolve_fork()`
- `ForkChoiceRule`: `HeaviestSubtree` (default) and `LongestChain`
- 33 tests (22 dag, 11 fork_choice)

**TLS — Fase C: Certificate Pinning**
- `CertPinConfig`: SHA-256 fingerprint allowlist; disabled when empty
- `PinningServerCertVerifier` / `PinningClientCertVerifier`: verify CA first, then fingerprint
- `TLS_PINNED_CERTS` env var (comma-separated); absent = pinning off
- `docs/NETWORK_MEMBERSHIP.md`: pinning section with rotation guide
- 32 TLS tests total

**TLS — Fase B: mTLS**
- `build_server_config_mtls` / `build_client_config_mtls`
- `TLS_MUTUAL=true` + `TLS_CA_CERT_PATH`; explicit error if CA missing
- 2 P2P integration tests (valid handshake, server rejects client without cert)

**TLS — Fase A: TLS básico**
- `src/tls.rs`: PEM loading, `ServerConfig`, `ClientConfig`, `PeerVerification` enum
- `TLS_CERT_PATH`, `TLS_KEY_PATH`, `TLS_VERIFY_PEER`, `TLS_CA_CERT_PATH`
- P2P connections wrapped in `TlsAcceptor` / `TlsConnector`
- Dependencies: `rustls 0.23`, `rustls-pemfile 2`, `tokio-rustls 0.26`, `webpki-roots 0.26`

**CI**
- Added `toolchain: stable` to all GitHub Actions workflows (required by `dtolnay/rust-toolchain@master`)

### Changed
- Docs reorganized: `ANALYSIS/` → `docs/analysis/`, `Documents/` → `docs/archive/`
- Stopped tracking local `blockchain_blocks/` sample data

