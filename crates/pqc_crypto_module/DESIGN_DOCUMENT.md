# Design Document — pqc_crypto_module v0.1.0

> **Disclaimer**: This module is prepared for FIPS 140-3 evaluation and is not currently validated.

---

## 1. Purpose

`pqc_crypto_module` is a Rust crate that isolates all cryptographic operations for the Cerulean Ledger DLT behind a single, auditable boundary. It provides post-quantum digital signatures (ML-DSA-65), key encapsulation (ML-KEM-768), and hashing (SHA3-256) with approved-mode enforcement, startup self-tests, and key zeroization.

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    DLT Application                      │
│         (src/identity/, src/consensus/, etc.)            │
└─────────────────────┬───────────────────────────────────┘
                      │ only via pqc_crypto_module::api
┌─────────────────────▼───────────────────────────────────┐
│              CRYPTOGRAPHIC BOUNDARY                      │
│                                                          │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │  api.rs   │──▶│ mldsa.rs │   │ mlkem.rs │            │
│  │ (entry   │──▶│          │   │          │            │
│  │  point)  │──▶│ hashing  │   │  rng.rs  │            │
│  └────┬─────┘   └──────────┘   └──────────┘            │
│       │                                                  │
│  ┌────▼─────────────┐  ┌───────────────┐               │
│  │ approved_mode.rs  │  │ self_tests.rs │               │
│  │ (state machine)   │  │ (KATs)        │               │
│  └──────────────────┘  └───────────────┘               │
│                                                          │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │ types.rs │   │ errors.rs│   │ legacy.rs │            │
│  │ (Zeroize)│   │          │   │ (gated)   │            │
│  └──────────┘   └──────────┘   └──────────┘            │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## 3. Cryptographic Boundary

The boundary is defined as all Rust source files under `crates/pqc_crypto_module/src/`. The Rust crate system enforces this: external code can only access `pub` items exported by the crate.

### Files inside the boundary

| File | Role |
|---|---|
| `lib.rs` | Crate root; re-exports public modules |
| `api.rs` | Public API entry point for all approved operations |
| `mldsa.rs` | ML-DSA-65 key generation, signing, verification |
| `mlkem.rs` | ML-KEM-768 key encapsulation (FIPS 203 via `aws-lc-rs`) |
| `hashing.rs` | SHA3-256 hashing |
| `rng.rs` | CSPRNG wrapper with continuous test |
| `self_tests.rs` | Known Answer Tests |
| `approved_mode.rs` | State machine (`AtomicU8`) and enforcement guards |
| `types.rs` | Typed wrappers for keys, signatures, hashes with `ZeroizeOnDrop` |
| `errors.rs` | `CryptoError` enum via `thiserror` |
| `legacy.rs` | Non-approved algorithms (gated; outside approved boundary) |

### Files outside the boundary

| Path | Role |
|---|---|
| `tests/*.rs` | Integration tests (verification only) |
| `Cargo.toml` | Build configuration |
| `*.md` | Documentation |

### Boundary enforcement

The boundary is enforced by:

1. **Rust module system**: Only `pub` items in `lib.rs` are accessible to external crates.
2. **`pub(crate)` visibility**: Internal functions (e.g., `*_raw` variants used by self-tests) are not accessible outside the crate.
3. **Integration tests**: `tests/api_boundary.rs` verifies that all operations fail before initialization. `tests/no_fallback.rs` verifies no classical algorithm fallback exists.

## 4. API Entry Points

All external access goes through `pqc_crypto_module::api`:

| Function | Input | Output | Guard |
|---|---|---|---|
| `initialize_approved_mode()` | None | `Result<(), CryptoError>` | Sets state to `SelfTesting`, runs KATs |
| `generate_mldsa_keypair()` | None | `Result<MldsaKeyPair, CryptoError>` | `require_approved()` |
| `sign_message(sk, msg)` | `&MldsaPrivateKey`, `&[u8]` | `Result<MldsaSignature, CryptoError>` | `require_approved()` |
| `verify_signature(pk, msg, sig)` | `&MldsaPublicKey`, `&[u8]`, `&MldsaSignature` | `Result<(), CryptoError>` | `require_approved()` |
| `sha3_256(data)` | `&[u8]` | `Result<Hash256, CryptoError>` | `require_approved()` |
| `generate_mlkem_keypair()` | None | `Result<MlKemKeyPair, CryptoError>` | `require_approved()` |
| `mlkem_encapsulate(pk)` | `&MlKemPublicKey` | `Result<(MlKemCiphertext, MlKemSharedSecret), CryptoError>` | `require_approved()` |
| `mlkem_decapsulate(sk, ct)` | `&MlKemPrivateKey`, `&MlKemCiphertext` | `Result<MlKemSharedSecret, CryptoError>` | `require_approved()` |
| `random_bytes(n)` | `usize` | `Result<Vec<u8>, CryptoError>` | `require_approved()` |

Every function except `initialize_approved_mode()` calls `require_approved()` as its first operation. If the module is not in `Approved` state, the function returns an error immediately without performing any cryptographic operation.

## 5. Data Flow

### Initialization flow

```
Caller ──> api::initialize_approved_mode()
              │
              ├── set_state(SelfTesting)
              ├── self_tests::run_all()
              │     ├── kat_sha3_256()
              │     ├── kat_mldsa65()
              │     ├── kat_mlkem()
              │     └── test_rng()
              │
              ├── [all pass] ──> set_state(Approved) ──> Ok(())
              └── [any fail] ──> set_state(Error)    ──> Err(CryptoError)
```

### Signing flow (representative of all approved operations)

```
Caller ──> api::sign_message(sk, msg)
              │
              ├── mldsa::sign_message(sk, msg)
              │     ├── require_approved()  ──> [not Approved?] ──> Err
              │     └── sign_message_raw(sk, msg)
              │           ├── PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, sk)
              │           ├── PqdsaKeyPair::sign(msg, &mut sig)
              │           └── MldsaSignature(sig_bytes)
              │
              └── Result<MldsaSignature, CryptoError>
```

### Legacy algorithm flow (blocked in Approved mode)

```
Caller ──> legacy::legacy_sha256(data)
              │
              ├── ensure_not_approved()
              │     └── [state == Approved] ──> Err(NonApprovedAlgorithm)
              │
              └── [state != Approved] ──> sha2::Sha256::digest(data)
```

## 6. Internal Components

### 6.1 State Machine (`approved_mode.rs`)

A global `AtomicU8` stores the module state. `SeqCst` ordering ensures visibility across threads. The state values are:

- `0` = `Uninitialized`
- `1` = `SelfTesting`
- `2` = `Approved`
- `3` = `Error`

Two guard functions enforce access:

- `require_approved()`: Returns `Ok(())` only if state is `Approved`.
- `ensure_not_approved()` (in `legacy.rs`): Returns `Ok(())` only if state is **not** `Approved`.

### 6.2 Self-Tests (`self_tests.rs`)

Runs four KATs sequentially. Any failure short-circuits and returns an error. See [SELF_TEST_DOCUMENTATION.md](SELF_TEST_DOCUMENTATION.md).

### 6.3 Type System (`types.rs`)

Wraps raw byte vectors in distinct newtypes (`MldsaPublicKey`, `MldsaPrivateKey`, `MldsaSignature`, `Hash256`, etc.). Private keys and shared secrets derive `ZeroizeOnDrop` to overwrite memory on drop. Debug implementations for sensitive types print `[REDACTED]`.

### 6.4 Error Handling (`errors.rs`)

`CryptoError` is defined via `thiserror` with variants for each failure mode:

- `ModuleNotInitialized` — operation before `initialize_approved_mode()`
- `ModuleInErrorState` — operation after self-test failure
- `SelfTestFailed(String)` — specific KAT failure description
- `InvalidKey(String)` — key format or size error
- `InvalidSignature` — signature format error
- `VerificationFailed` — signature did not verify
- `RngFailure(String)` — CSPRNG error
- `NonApprovedAlgorithm` — legacy algorithm called in Approved mode
- `SerializationError(String)` — serialization failure

### 6.5 RNG (`rng.rs`)

Wraps `rand::rngs::OsRng` for all randomness. Provides:

- `fill_random(buf)` — fill a buffer with random bytes
- `random_bytes(n)` — allocate and fill n random bytes
- `continuous_rng_test()` — generate two 32-byte samples and verify they differ

### 6.6 Legacy Module (`legacy.rs`)

Contains non-approved algorithms (Ed25519, SHA-256, HMAC-SHA256) behind runtime guards. When compiled with `--features approved-only`, the entire module is excluded via `compile_error!`. See [NON_APPROVED_USAGE.md](NON_APPROVED_USAGE.md).

## 7. Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `aws-lc-rs` | 1.19 | ML-DSA-65 and ML-KEM-768 implementation |
| `pqcrypto-traits` | 0.3 | Traits for PQC types |
| `sha3` | 0.10 | SHA3-256 |
| `sha2` | 0.10 | SHA-256 (legacy only) |
| `hmac` | 0.12 | HMAC (legacy only) |
| `ed25519-dalek` | 2.1 | Ed25519 (legacy only) |
| `rand` | 0.8 | CSPRNG wrapper |
| `rand_core` | 0.6 | `getrandom` backend |
| `zeroize` | 1.7 | Memory zeroization |
| `thiserror` | 1.0 | Error type derivation |
| `hex` | 0.4 | Hex encoding for hash output |

Dependencies `sha2`, `hmac`, and `ed25519-dalek` are used only by the `legacy` module and are excluded from the approved boundary.
