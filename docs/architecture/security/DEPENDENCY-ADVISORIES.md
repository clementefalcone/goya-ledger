# Dependency advisories

`cargo audit` runs in the cloud gate and fails the build on any RustSec
advisory not in the acknowledged baseline below. The baseline lives in
`.cargo/audit.toml`; every entry is a known advisory with no compatible fix
today (the vulnerable crate is transitive under a parent that pins the old
major, or it is not present in the production binary). A new advisory — one
not listed here — stops the gate.

"In production" means reachable through normal dependency edges in the
`rust-bc` binary (`cargo tree -i <crate> -e normal`). Test-only, dev-only and
feature-gated crates (for example the `acvp` test feature) are not in the
deployed node.

## Not in the production binary (11)

| Advisory | Crate | Why it is not in production |
|---|---|---|
| RUSTSEC-2026-0586 | pqcrypto-mldsa 0.1.2 | `acvp` test feature only; production ML-DSA is aws-lc-rs |
| RUSTSEC-2026-0585 | pqcrypto-mlkem 0.1.1 | `acvp` test feature only; production ML-KEM is aws-lc-rs |
| RUSTSEC-2026-0286 | cryptoki 0.7.0 | not in the normal dependency graph |
| RUSTSEC-2026-0346 | rustls 0.21.12 | old transitive rustls; production TLS is rustls 0.23 |
| RUSTSEC-2026-0349 | rustls 0.21.12 | same; the PQ-TLS path uses rustls 0.23 |
| RUSTSEC-2026-0104 | rustls-webpki 0.101.7 | old transitive; production uses rustls-webpki 0.103 |
| RUSTSEC-2026-0098 | rustls-webpki 0.101.7 | same |
| RUSTSEC-2026-0099 | rustls-webpki 0.101.7 | same |
| RUSTSEC-2026-0382 | rustls-webpki 0.101.7 | same |
| RUSTSEC-2026-0381 | webpki-roots 0.25.4 | not in the normal dependency graph; the validator mesh verifies against a private CA, not webpki-roots |
| RUSTSEC-2025-0055 | tracing-subscriber 0.2.25 | not in the normal dependency graph |

## In the production binary (5)

| Advisory | Crate | Status |
|---|---|---|
| RUSTSEC-2023-0071 | rsa 0.9.10 | Marvin timing side-channel on RSA private-key operations observable over the network. Direct dependency, but the vulnerable path is not reachable in the deployed node: every RSA signing and key-generation call site is test-gated, there is no RSA decryption anywhere, and production only ever verifies RSA signatures (public key, no secret, no timing leak). The node's own TSA, OCSP and certificates sign with ECDSA-P256, not RSA. The fix (rsa 0.10) forces sha2 0.10→0.11 across the whole crypto surface — a disproportionate migration for an unreachable path — so rsa stays at 0.9 and this advisory stays acknowledged. |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 | Timing variability. Transitive under k256 (EVM secp256k1); fix needs k256 to move to crypto-bigint 0.7. |
| RUSTSEC-2026-0258 | h2 0.3.27 | Unbounded empty DATA frames (DoS). Transitive under actix-web; no actix release on h2 0.4. Mitigated by the API rate limits. |
| RUSTSEC-2026-0594 | cookie 0.16.2 | Private-cookie nonce repeat on fork. Transitive under actix-web; the API does not issue private session cookies (DID/token auth). |
| RUSTSEC-2024-0437 | protobuf 2.28.0 | Recursion crash parsing malformed protobuf. Transitive under prometheus/raft; used for metrics encoding, not untrusted input. |

## Unmaintained warnings

`cargo audit` also reports unmaintained crates (bincode, chrono, derivative,
fxhash, paste, proc-macro-error, the pqcrypto-* crates). These are warnings,
not vulnerabilities, and do not fail the gate.

## Maintaining the baseline

When an upstream parent updates, drop the crate's advisory from
`.cargo/audit.toml`, run `cargo update`, and confirm `cargo audit` stays
green. Never add an entry without recording here why no fix applies.
