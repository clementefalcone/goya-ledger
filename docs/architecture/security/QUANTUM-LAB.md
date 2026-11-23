# Quantum Pentest Lab

Black-box attacks against a 4-validator Goya network, run 2026-11-22 on branch `feat/quantum-lab`.
Scripts live in `scripts/attack-lab/`.

**Honesty note.** No quantum computer is involved. Shor is *simulated*: the attacker is handed the
classical private key that Shor would recover. What the lab measures is real: what Goya accepts once a
classical key has fallen.

## How to run

```bash
python -m venv .venv && .venv/bin/pip install -r scripts/attack-lab/requirements.txt
export GOYA_NODE_BIN=target/debug/rust-bc
scripts/attack-lab/network.sh keygen && scripts/attack-lab/network.sh start
.venv/bin/python scripts/attack-lab/attack_suite.py           # 16 protocol attacks
.venv/bin/python scripts/attack-lab/quantum_inventory.py      # exposure inventory
.venv/bin/python scripts/attack-lab/quantum_migration.py <legacy-bin> <current-bin>
.venv/bin/python scripts/attack-lab/quantum_downgrade.py      # downgrade and alg confusion
```

## 1. Exposure inventory (`quantum_inventory.py`)

| Surface | Algorithm | On Q-day |
|---|---|---|
| Block signatures (except genesis), DIDs, node login session key | ML-DSA-65 | holds |
| Credential signatures (OID4VCI) | ES256 | forgeable; mitigated by the ML-DSA anchor (§3) |
| Holder proof of possession | ES256 / EdDSA / RS256 | classical, open |
| Issuer credential key | P-256 | private key derivable |
| Node TLS certificates (rcgen) | ECDSA-P256 | classical, open |
| Genesis block | Ed25519 | historical |

## 2. Q-day takeover of legacy identities (`quantum_migration.py`)

Ed25519 identities created by the binary that predates mandatory ML-DSA, attacked after the upgrade.

| Attack | Before 393898e | After |
|---|---|---|
| Log in as the victim | OPEN 200 | CLOSED 400 |
| Add an attacker device to the vault | OPEN 201 | CLOSED 400 |
| Commit an attacker recovery key | OPEN 201 | CLOSED 400 |
| Rotate the DID to the attacker's key (permanent takeover) | OPEN 200 | CLOSED 409 |
| Revoke the victim | OPEN 200 | CLOSED 400 |
| Notarize as the victim | CLOSED 400 | CLOSED 400 |

Fix 393898e freezes classical-key identities at the API boundary. Block validation is untouched, so history
still replays. Production held 12 Ed25519 identities (2 active) on 2026-11-22; they are frozen with no
migration path and their owners must register a new ML-DSA DID.

## 3. Downgrade and algorithm confusion (`quantum_downgrade.py`)

| Attack | Result |
|---|---|
| CONTROL: holder presents an anchored credential | accepted 200 |
| Shor-forged ES256 credential | rejected 400 |
| alg confusion: EdDSA by an attacker key | rejected 400 |
| alg confusion: `alg=none` | rejected 400 |
| alg confusion: HS256 keyed with the issuer's public JWK | rejected 400 |
| Stolen credential with the thief's key binding | **200 before 9c1461d**, rejected 400 after |
| Ed25519 signature labelled ML-DSA-65 | rejected 401 |
| Ed25519 key registered as ML-DSA-65 | rejected 400 |
| Rotate an ML-DSA identity to a classical key | rejected 400 |
| Classical reader key in the vault | rejected 400 |

- 4bf4bc4: the OID4VP verifier resolves the issuer key from the ledger and requires the issuer's ML-DSA
  anchor. The in-memory key registry it replaced had no production writer.
- 9c1461d: the verifier requires a KB-JWT signed by the key in `cnf.jwk`. This flaw was classical, not
  quantum.

**Production TLS, measured 2026-11-22.** nginx on the VPS (OpenSSL 3.0.13) negotiates X25519 only and
refuses an X25519MLKEM768-only client (alert 40). Traffic to the apps that call Goya can be harvested
today and decrypted later. P2P 8081 runs without TLS (no `TLS_*` in `/etc/goya-node/env`) but UFW
denies it from the internet; it needs TLS before external validators join.

## 4. Grover margins

Grover's algorithm halves the exponent of brute-force search. The target is ≥128 quantum bits.

| Primitive | Where | Classical | Quantum (Grover / BHT) | Verdict |
|---|---|---|---|---|
| AES-256-GCM | `pqc_crypto_module::encrypt` (ML-KEM hybrid) | 256 | 128 | ok |
| SHA3-512 | DID derivation | 512 preimage | 256 preimage, ~170 collision | ok |
| SHA-256 | anchors, `_sd` digests, commitments | 256 preimage | 128 preimage, ~85 collision | ok (BHT needs impractical memory) |
| HMAC-SHA-256, 32-byte secrets | checkpoints, pairwise ids | 256 | 128 | ok |
| SHA-256 truncated to 160 bits | wallet-address DIDs (`wallet_address_of`) | 160 second preimage | **80** | below target |
| 32-byte disclosure salts (16 before 2026-11-22) | SD-JWT `generate_salt`, mdoc `random` | 256 | 128 | ok; credentials issued with 16-byte salts keep 64 quantum bits |
| 4–6 digit PIN, Argon2id | `src/pin` | ≤20 | ≤10 | brute-forceable classically; only rate limiting protects it |

## Open items

1. Wallet-address DIDs: 160-bit truncation. A format change, needs a decision.
2. PQ TLS on the VPS: OpenSSL ≥ 3.5 or a proxy with X25519MLKEM768. P2P TLS before external validators join.
3. Holder proofs and issuer credential keys stay classical while EUDI wallets require ES256.
4. Node certificates are ECDSA-P256.
