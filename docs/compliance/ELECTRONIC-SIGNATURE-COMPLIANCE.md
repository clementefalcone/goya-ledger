# Electronic Signature Compliance

Legal alignment mapping for the GOYA Ledger electronic signature framework.

Covers four jurisdictions: Chile, European Union, United States, and UAE.

For detailed UAE compliance mapping, see [UAE-COMPLIANCE.md](UAE-COMPLIANCE.md).

> **Disclaimer:** This document is a **self-assessment** mapping code features to legal requirements. It is not a certification, legal opinion, or formal audit result. No third-party auditor or legal authority has validated these claims. Organizations should seek independent legal counsel before relying on these mappings for compliance purposes.

---

## Signature levels implemented

| Level | Algorithm | Biometric | Code path |
|-------|-----------|-----------|-----------|
| **Simple (FES)** | Ed25519 | Optional | `SignatureLevel::Simple` |
| **Advanced (FEA)** | ML-DSA-65 (FIPS 204) | Required (>=1) | `SignatureLevel::Advanced` |
| **Qualified** | ML-DSA-65 | Required | `SignatureLevel::Qualified` (reserved) |

Biometric evidence is stored as SHA-256 commitments only. Raw biometric data never enters the system.

> **Important limitation:** Biometric commitments are **unverified, client-asserted** data. The system accepts whatever SHA-256 hash the client sends and does not verify that the hash corresponds to a real biometric template, a live capture, or the claimed biometric type. There is no liveness detection, no template quality check, and no trusted biometric capture device requirement. This means the biometric binding provides cryptographic integrity (the commitment is bound to the signature) but not identity assurance (anyone with the signing key can submit any hash as "biometric evidence").

---

## Chile — Ley 19.799

**Ley 19.799 sobre Documentos Electrónicos, Firma Electrónica y Servicios de Certificación** (2002, modified 2019).

### Art. 2° — Definitions

| Legal concept | GOYA implementation | Status |
|---|---|---|
| **Firma electrónica** (simple): cualquier sonido, símbolo o proceso electrónico que permita al receptor identificar formalmente a su autor | `SignatureLevel::Simple` — Ed25519 DID-based signature over content hash. Signer identified by `did:goya:{pubkey}` | Done |
| **Firma electrónica avanzada**: creada usando medios bajo control exclusivo del signatario, vinculada a datos de tal forma que se detecte cualquier modificación ulterior | `SignatureLevel::Advanced` — ML-DSA-65 private key (sole control) + biometric commitment bound to signing payload (tamper detection via PQC signature) | Done |

### Art. 3° — Legal validity

| Requirement | Implementation |
|---|---|
| FES admisible como medio de prueba | Every `NotarizationEntry` with `Simple` level is stored with block height, timestamp, and signature — constitutes proof of existence |
| FEA equivale a firma manuscrita cuando emitida por prestador acreditado | `Advanced` level uses post-quantum ML-DSA-65 + biometric identity binding. Qualified TSP integration reserved for `SignatureLevel::Qualified` |

### Art. 5° — No discriminación

| Requirement | Implementation |
|---|---|
| No se negará validez jurídica a una firma por el solo hecho de ser electrónica | Both FES and FEA produce verifiable, auditable records with cryptographic proof |

### Art. 15° — Certificación

| Requirement | Implementation | Status |
|---|---|---|
| Prestador de servicios de certificación debe estar acreditado | `Qualified` level reserved for integration with Chilean-accredited PSC (Prestador de Servicios de Certificación) | Planned |

---

## European Union — eIDAS Regulation 910/2014

**Regulation (EU) No 910/2014 on electronic identification and trust services for electronic transactions in the internal market.**

### Art. 3 — Definitions

| eIDAS concept | GOYA implementation | Article |
|---|---|---|
| **Electronic signature** (Art. 3.10): data in electronic form attached to or associated with other electronic data, used by the signatory to sign | `SignatureLevel::Simple` — Ed25519 signature over `"notarize:{signer}:{hash}"` | Art. 3(10) |
| **Advanced electronic signature** (Art. 3.11): uniquely linked to signatory, capable of identifying signatory, created using data under sole control, linked to data so change is detectable | `SignatureLevel::Advanced` — see compliance table below | Art. 3(11) |
| **Qualified electronic signature** (Art. 3.12): advanced signature created by QSCD and based on qualified certificate | `SignatureLevel::Qualified` — reserved for QTSP integration | Art. 3(12) |

### Art. 26 — Advanced electronic signature requirements

| Requirement | GOYA control | Evidence |
|---|---|---|
| **(a)** Uniquely linked to the signatory | DID (`did:goya:{pubkey}`) + biometric commitment(s) hashed into signing payload | `compute_biometrics_hash()` bound to payload |
| **(b)** Capable of identifying the signatory | Biometric evidence types: fingerprint, facial recognition, RUT, iris, voice, government ID. External identity verification supported via `IdentityVerificationProvider` trait (`src/identity/ra.rs`). `RaStore::submit_and_verify()` calls an external IdP and links the verified identity to the DID before allowing AdES signing. **Deployment note:** the `SimulatedIdentityVerifier` is for testing only — production deployments must plug in a real adapter (ClaveÚnica, eID, video-ident) to satisfy Art. 26(b) | `BiometricType` enum, `BiometricEvidence.commitment`, `IdentityVerificationProvider` trait |
| **(c)** Created using electronic signature creation data under sole control of the signatory | ML-DSA-65 private key generated client-side, never transmitted. Key encrypted with Argon2id + AES-256-GCM | Client-side key management, `pqc_crypto_module` |
| **(d)** Linked to the data signed so that any subsequent change is detectable | PQC signature (ML-DSA-65, 3309-byte) covers signer DID + content hash + biometric commitments hash | Signing payload: `"notarize_fea:{s}:{h}:{bio_hash}"` |

### Art. 25 — Legal effects

| Provision | GOYA compliance |
|---|---|
| Art. 25(1): electronic signature not denied legal effect solely on grounds it is in electronic form | All signature levels produce verifiable records stored on-chain |
| Art. 25(2): qualified electronic signature has equivalent legal effect of handwritten signature | `Qualified` level reserved for QTSP-issued certificates |

### Art. 28 — Qualified certificates

| Requirement | Status |
|---|---|
| Issued by qualified trust service provider (QTSP) listed in EU Trusted List | Planned — `Qualified` level will require external QTSP certificate chain validation |

### Regulation (EU) 2024/1183 — eIDAS 2.0

| Enhancement | GOYA readiness |
|---|---|
| European Digital Identity Wallet (EUDI) | DID-based identity model compatible with wallet architecture |
| Qualified Electronic Attestation of Attributes (QEAA) | Verifiable Credentials (`Credential` type) with issuer DID and cryptographic signature |
| Post-quantum readiness recommendation | ML-DSA-65 (FIPS 204) already deployed for Advanced/Qualified levels |

---

## United States — ESIGN Act + UETA

### ESIGN Act (15 U.S.C. §7001–7006)

**Electronic Signatures in Global and National Commerce Act** (2000).

| Provision | GOYA compliance |
|---|---|
| **§7001(a)**: signature or contract not denied legal effect solely because in electronic form | Both Simple and Advanced produce cryptographic signatures stored with audit trail |
| **§7001(d)**: consumer consent requirements | Application layer responsibility (outside blockchain scope) |
| **§7006(5)** definition: "electronic, digital, or analog process attached to a contract or record, executed or adopted by a person with intent to sign" | Ed25519 and ML-DSA-65 signatures are electronic processes executed with explicit signer intent (signing payload construction) |

### UETA (Uniform Electronic Transactions Act)

Adopted by 49 states + DC + USVI. Provides state-level parity with ESIGN.

| UETA section | GOYA compliance |
|---|---|
| **§2(8)**: electronic signature = electronic sound, symbol, or process | Ed25519/ML-DSA-65 digital signatures qualify |
| **§7**: legal recognition of electronic records and signatures | On-chain notarization with block height anchoring provides immutable record |
| **§9**: attribution — attributable to person if act of that person | DID↔public key binding via `did_matches_pubkey()` + biometric commitment for FEA |
| **§12**: record retention satisfied by electronic record | `NotarizationEntry` persisted to RocksDB with content hash, timestamp, block height, signature |

---

## NIST standards alignment

| Standard | Application | Status |
|---|---|---|
| **FIPS 204** (ML-DSA) | Post-quantum signature algorithm for FEA | ML-DSA-65 (security level 3) via `pqc_crypto_module` |
| **FIPS 186-5** | Ed25519 for FES | `SoftwareSigningProvider` via `ed25519_dalek` |
| **FIPS 202** | SHA-3 for alias commitments | SHA3-256 via `pqc_crypto_module` |
| **SP 800-63B** | Digital identity assurance levels | FES ~ AAL1 (single factor). FEA is a structural analogy to AAL2 (cryptographic key + biometric), but not equivalent — AAL2 requires identity verification through a trusted provider and verified biometric enrollment, whereas GOYA accepts self-asserted biometric hashes without external identity proofing |
| **SP 800-185** | Vault recovery via KDF | HMAC-SHA3-256 blind index for recovery keys |

---

## Biometric evidence handling

### Privacy by design

| Principle | Implementation |
|---|---|
| **Data minimization** | Only SHA-256 commitment stored, never raw biometric data |
| **Purpose limitation** | Commitments used exclusively for signature binding |
| **No reversibility** | SHA-256 is one-way — commitment cannot recover biometric template |
| **Client-side processing** | Biometric capture and hashing performed on client device |
| **No central biometric database** | Node stores only commitments, not templates |

### GDPR considerations (EU)

| Article | Assessment |
|---|---|
| Art. 9 — Special categories (biometric data) | System stores SHA-256 hashes, not biometric data. Recital 51 clarifies processing must enable unique identification — one-way hashes do not. Legal basis: legitimate interest (Art. 6.1.f) or consent (Art. 6.1.a) depending on deployment |
| Art. 25 — Data protection by design | Commitment-only architecture prevents biometric data exposure |
| Art. 35 — DPIA | Recommended for deployments processing biometric commitments at scale |

### Chilean data protection (Ley 19.628 / Ley 21.719)

| Requirement | Assessment |
|---|---|
| Datos personales sensibles (Art. 2° Ley 19.628) | SHA-256 commitments are derived data, not biometric data per se. Conservative approach: treat as sensitive and require consent |
| Ley 21.719 (2024) — new data protection framework | Aligns with GDPR. Same commitment-only approach applies |

---

## Endpoint coverage matrix

All endpoints that accept cryptographic signatures support both FES and FEA:

| Endpoint | Simple payload | Advanced payload |
|---|---|---|
| `POST /notarize` | `notarize:{s}:{h}` | `notarize_fea:{s}:{h}:{bio}` |
| `POST /notarize/{h}/transfer` | `transfer_doc:{h}:{n}:{f}:{t}` | `transfer_fea:{h}:{n}:{f}:{t}:{bio}` |
| `POST /governance/vote/{id}` | `vote:{id}:{opt}:{pk}` | `vote_fea:{id}:{opt}:{pk}:{bio}` |
| `POST /inference/submit` | `inference:submit:{m}:{o}` | `inference:submit:{m}:{o}:{bio}` |
| `POST /inference/submit-proven` | `inference:submit:{m}:{o}` | `inference:submit:{m}:{o}:{bio}` |
| `POST /inference/challenge` | `challenge:{id}:{h}` | `challenge:{id}:{h}:{bio}` |
| `POST /alias/register` | `alias:register:{c}` | `alias:register:{c}:{bio}` |
| `POST /alias/revoke` | `alias:revoke:{c}` | `alias:revoke:{c}:{bio}` |
| `POST /governance/invitations` | `{to}:{ids}` | `{to}:{ids}:{bio}` |
| `POST /governance/invitations/respond` | `{id}:{accepted}` | `{id}:{accepted}:{bio}` |
| `POST /identity/verify-signature` | auto-detect Ed25519/ML-DSA-65 | auto-detect |

Where `{bio}` = `SHA-256(sorted biometric commitments joined by ':')`.

---

## Roadmap

| Item | Status | Target |
|---|---|---|
| Simple (FES) — Ed25519 | Done | — |
| Advanced (FEA) — ML-DSA-65 + biometric | Done | — |
| Qualified — QTSP certificate chain validation | Planned | When certified TSP available |
| Timestamping Authority (TSA) integration — RFC 3161 | Done | — |
| Long-term signature preservation — CAdES/XAdES/PAdES | Done | — |
| eIDAS 2.0 EUDI Wallet interop | Planned | EU Digital Identity Wallet compatibility |
| Chilean PSC (Prestador de Servicios de Certificación) integration | Planned | Accredited provider for FEA certification |
| UAE TDRA QTSP licensing | Planned | When applying for TDRA trust service provider |
| UAE Pass identity verification (live API) | Planned | Real-time Emirates ID verification |
| UAE Emirates ID validation | Done | `validate_emirates_id()` in RA module |
| Multi-jurisdiction RA (Chile/UAE/EU) | Done | `Jurisdiction` enum + `validate_national_id()` |
