# Identity Architecture

Digital identity subsystem: DIDs, credentials, key management, and authentication.

## Module Map

```
src/identity/
├── did.rs            DID derivation: did:goya:{pubkey_hex[..16]}
├── signing.rs        SigningProvider trait + 5 algorithms
├── keys.rs           KeyManager: rotation, migration, DID chain
├── key_recovery.rs   Shamir SSS over GF(256), zero dependencies
├── dual_signing.rs   Classical + PQC dual signatures (migration)
├── hsm.rs            PKCS#11 HSM provider (feature-gated)
├── sd_jwt.rs         SD-JWT VC (RFC 9901 + key binding)
├── mdoc.rs           ISO 18013-5 mDL/PID credentials
├── status_list.rs    IETF Token Status List (revocation)
├── attestation.rs    EUDI ARF v3.0 attestation types
├── ra.rs             Registration Authority (multi-jurisdiction)
├── pqc_policy.rs     PQC enforcement + tag forgery prevention
├── zkp.rs            Commitment proofs (not ZKP — documented)
└── mod.rs            Module re-exports
```

## DID Scheme

Format: `did:goya:{pubkey_hex[..16]}`

- Deterministic: derived from first 8 bytes of public key hex
- Self-verifying: `did_matches_pubkey(did, pubkey_hex)` confirms ownership
- Single method (`did:goya:`), no DID method resolution infrastructure

Canonical derivation: `identity::did::did_from_pubkey_hex()`. All DID generation must use this function.

## Signing Algorithms

| Algorithm | Standard | PK Size | Sig Size | Use |
|-----------|----------|---------|----------|-----|
| Ed25519 | RFC 8032 | 32 B | 64 B | Default, classical |
| ML-DSA-65 | FIPS 204 | 1952 B | 3309 B | Post-quantum primary |
| SLH-DSA-128s | FIPS 205 | 32 B | 7856 B | PQC backup (stateless) |
| RSA-2048 | PKCS#1 v1.5 | 256 B | 256 B | Legacy interop |
| ECDSA P-256 | NIST SP 800-186 | 33/65 B | 64 B | eIDAS / WebAuthn |

All algorithms implement `SigningProvider` trait: `sign()`, `verify()`, `public_key()`, `algorithm()`.

FIPS 140-3 Known Answer Tests run at startup via `run_crypto_self_tests()`.

## Key Lifecycle

```
register (DID fixed by first key, commits SHA3-512 of an ML-DSA-65 recovery key)
  → active ⇄ revoked (revoke: signed by current key)
  → rotate (signed by the committed recovery key + the new key; same DID,
            new signing key, fresh recovery commitment; restores revoked)
  → split (Shamir SSS for backup)
```

- `KeyManager` tracks active + retired keys with timestamps
- Register, revoke and rotate are `TxPayload` transactions: every node re-verifies signatures when it applies the block (`identity::operations`)
- Rotation is the PQC migration path: an Ed25519 identity rotates to an ML-DSA-65 key and keeps its DID; the recovery key must be ML-DSA-65 so a broken classical algorithm cannot authorize it
- A stolen device cannot rotate: it holds the current key, not the recovery key; after rotation the stolen key fails every identity operation on every node
- An identity registered without a recovery commitment can commit one once (`POST /identity/{did}/recovery`, `TxPayload::CommitRecoveryKey`), signed by its current key over `identity:recovery:commit:{did}:{commitment}`; once set, only rotation by the recovery key replaces it (`identity::recovery_commitment`)
- `key_recovery::split(secret, threshold, total)` produces N shares; any K reconstruct via Lagrange interpolation over GF(256)

### HSM Support

Behind `hsm` feature flag. `HsmSigningProvider` wraps PKCS#11:
- Config via env vars: `HSM_PKCS11_LIB`, `HSM_SLOT_ID`, `HSM_PIN`, `HSM_KEY_LABEL`
- `SimulatedHsmProvider` for testing without hardware
- Session management: open/close/reopen with PIN

## Credential Formats

### SD-JWT VC (RFC 9901)

- Selective disclosure via SHA-256 disclosure hashing
- Holder key binding: `cnf.jkt` (JWK thumbprint, RFC 7638)
- KB-JWT verification with `sd_hash` binding
- JWT algorithm mapping for all 5 signing algorithms

### mdoc (ISO 18013-5)

- CBOR-encoded Mobile Security Object with per-element SHA-256 digests
- COSE_Sign1 issuer authentication
- Device authentication via `DeviceAuth` + `SessionTranscript`
- Selective disclosure by namespace/element

### Revocation

IETF Token Status List (draft-ietf-oauth-status-list):
- 2-bit per entry: Valid (0x00), Invalid (0x01), Suspended (0x02)
- Random index allocation (prevents correlation)
- JWT-signed status list with ZLIB compression
- SHA-256 anchor hash for DLT anchoring

## Authentication

### DID Auth (challenge-response)

```
Client                          Server
  │                                │
  ├─ POST /identity/auth/challenge │
  │  { did }                       │
  │                                ├─ verify DID exists
  │                ← challenge ────┤  generate nonce (UUID v4)
  │                                │  store with 5 min TTL
  │                                │
  ├─ POST /identity/auth/verify    │
  │  { did, challenge, signature } │
  │                                ├─ remove nonce (single-use)
  │                                ├─ read IdentityRecord
  │                                ├─ verify signature vs public_key
  │          ← authenticated ──────┤
```

- Algorithm resolved from `IdentityRecord.signature_algorithm`
- Supports Ed25519 and ML-DSA-65
- Optional `device_factors` (`pin`, `passphrase`, `biometric`) are checked on the device. When present, the signature must cover `identity:login:{nonce}:{factors joined by ","}` in the order sent; otherwise it covers the bare nonce. A repeated factor returns 400.
- The session JWT carries `verified_factors` (checked by the node, today `["key"]`) and `device_factors` (asserted by the device, bound by the signature). Apps requiring multiple factors read both.
- The session JWT is signed by the node's signing key; its header `alg` names that key (`ML-DSA-65` or `EdDSA`). Apps fetch the key from `GET /identity/auth/session-key` (`{issuer, alg, public_key}`) and verify `{header}.{payload}` against it. A node without a signing key refuses to issue tokens (500).

### Identity vault (per-device sealed keys)

`IdentityRecord.vault_entries` holds encrypted copies of the DID secret key, one per device passkey (`kind: device`, sealed with the passkey PRF secret) and one per recovery code (`kind: recovery`). The node never decrypts `sealed_key`; it only stores and replicates it.

- `POST /identity/{did}/vault` adds a copy. The current key of the DID signs `identity:vault:add:{did}:{entry_id}:{kind}:{sha3_256(label)}:{sha3_256(sealed_key)}`. `added_at` is set by the node and is not signed; retrying the same content is idempotent.
- `POST /identity/{did}/vault/{entry_id}/revoke` marks a copy revoked; signature over `identity:vault:revoke:{did}:{entry_id}`.
- Both travel in blocks (`TxPayload::AddVaultEntry`, `TxPayload::RevokeVaultEntry`) and every node re-verifies the signature.
- Read with `GET /store/identities/{did}`.
- Revoking a copy does not change the DID key. After a device is stolen, rotate the key and reseal the remaining devices.

### ACL System

`src/acl/` — resource-based access control enforced via `enforce_acl()` on protected endpoints.

## W3C Interoperability

### DID Resolution

`GET /api/v1/did/{did}` returns W3C DID Core compliant document:

- `@context` includes algorithm-appropriate security suite
- `verificationMethod` with correct type per algorithm
- `authentication` and `assertionMethod` as references
- Content-Type: `application/did+ld+json`

### VC Export

`GET /api/v1/credentials/{id}/vc` returns W3C VC Data Model 2.0:

- Proof type resolved from issuer's `signature_algorithm`
- `proofPurpose: assertionMethod`

## Registration Authority

Multi-jurisdiction identity proofing in `ra.rs`:

| Jurisdiction | Validation | Standard |
|-------------|------------|----------|
| Chile | RUT modulo 11 | Ley 19.799 |
| UAE | Emirates ID + Luhn | Federal Law No. 46/2021 |
| EU | eIDAS LoA (Low/Substantial/High) | eIDAS Art. 24 |

External verification via `IdentityVerificationProvider` trait. Smart-ID integration for Estonian e-ID.

## EUDI Compliance

`attestation.rs` implements ARF v3.0:
- Attestation types: PID, EAA, QEAA, PuB-EAA
- Issuer roles: PidProvider, TSP, QTSP, PublicBody
- PID prerequisite enforcement (CIR 2024/2977)
- Fail-closed 6-step authorization check

## Storage

`IdentityRecord` in `storage/traits.rs`:

| Field | Type | Description |
|-------|------|-------------|
| did | String | `did:goya:{...}` |
| public_key | String | Hex-encoded public key |
| signature_algorithm | Option\<String\> | Ed25519, MlDsa65, etc. |
| status | String | active, revoked, migrated (legacy DID format only) |
| migrated_from | Option\<String\> | Previous legacy-format DID |
| recovery_commitment | Option\<String\> | `did_from_pubkey_hex` of the committed recovery key |
| created_at | u64 | Unix timestamp |
| updated_at | u64 | Unix timestamp |

Light client: `LocalIdentityStore` persists identities as JSON in `~/.goya/identities.json`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /identity/create | Create DID + keypair |
| GET | /identity/{did} | Fetch identity |
| POST | /identity/{did}/verify-signature | Verify signature |
| POST | /identity/{did}/revoke | Revoke (current key) |
| POST | /identity/{did}/rotate | Rotate key with recovery key (same DID) |
| POST | /identity/auth/challenge | DID Auth: get nonce |
| POST | /identity/auth/verify | DID Auth: verify signature |
| GET | /identity/auth/session-key | Public key that signs session JWTs |
| GET | /did/{did} | W3C DID Resolution |
| POST | /credentials/issue | Issue credential |
| GET | /credentials/{id} | Fetch credential |
| GET | /credentials/{id}/vc | W3C VC export |
| POST | /credentials/{id}/verify | Verify credential |
| POST | /credentials/{id}/revoke | Revoke credential |

OpenID4VCI and OpenID4VP endpoints in `oid4vci.rs` and `oid4vp.rs`.

## Stats

- 14 source files, ~7000 lines
- 285 unit tests in identity module
- 5 cryptographic algorithms with FIPS KAT
- 3 credential formats (SD-JWT VC, mdoc, status list)
- 3 jurisdictions (Chile, UAE, EU)
