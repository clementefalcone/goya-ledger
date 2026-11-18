# Issuer Guide — credentials for EUDI wallets

Goya never signs credentials in its own name. Any DID can issue: the issuer signs every credential with its own keys, the node checks the signatures, delivers the credential to the wallet and records it on chain. Verifiers decide which issuers they trust.

## Keys

| Key | Algorithm | Purpose |
|---|---|---|
| DID key | Ed25519 or ML-DSA-65 | Controls the DID. Signs offers, the credential key binding, pending-list requests and the post-quantum anchor of each credential. |
| Credential key | ES256 (P-256) | Signs SD-JWT VCs and status lists, as required by EUDI wallets. Bound to the DID by a signature of the DID key, replicated on chain. |

Each credential carries two signatures from the same issuer: ES256 in the SD-JWT VC for wallet compatibility, and a DID-key signature over the SD-JWT's issuer JWT hash, recorded at `/store/credentials/sd-jwt:<sha256>`. The second stays verifiable if ES256 is broken.

## Flow

1. **Register the issuer DID** — `POST /store/identities` signed over `identity:register:{did}`.
2. **Bind the credential key** — `POST /issuers/{did}/credential-key`, signed over `oid4vci:issuer-key:{did}:{x}:{y}:{registered_at}`.
3. **Offer** — `POST /credential_offer` signed over `oid4vci:offer:{did}:{configuration_id}:{issued_at}`. The wallet scans the returned `openid-credential-offer://` URI.
4. **Wallet requests** — token, `/nonce`, then `/credential` with a proof of its key. The node answers 202 with a `transaction_id`.
5. **Issuer signs and delivers** — reads `GET /issuers/{did}/issuances` (signed over `oid4vci:pending:{did}:{issued_at}`), builds the SD-JWT VC with `iss = https://{host}/api/v1/issuers/{did}`, `cnf` = the wallet key and the configuration's `vct`, then `POST /issuers/{did}/issuances/{transaction_id}`. The node rejects anything not signed by the bound credential key or not matching the request.
6. **Anchor** — `POST /store/credentials` with id `sd-jwt:<sha256 of the issuer JWT>` and the same hash as `claims_commitment`, signed by the DID key.
7. **Wallet receives** — `/deferred_credential` returns the credential once.
8. **Revoke** — publish a newer status list with the index set (`PUT /issuers/{did}/status-lists/{list_id}`) and revoke the anchor (`POST /store/credentials/{id}/revoke`).

## CLI

`cerulean` keeps the DID key and the credential key in `~/.cerulean/wallet.json`.

```bash
cerulean --node https://node.example init "Clinic X"
cerulean --node https://node.example issuer register-credential-key
cerulean --node https://node.example issuer offer eudi_pid_sd_jwt
cerulean --node https://node.example issuer pending
cerulean --node https://node.example issuer deliver <transaction_id> claims.json --status-list main --status-index 42
cerulean --node https://node.example issuer status publish main
cerulean --node https://node.example issuer status publish main 42
```

`claims.json` is a JSON object; each member becomes a selectively disclosable claim. `issuer status publish <list_id> [indices...]` publishes the list with those indices revoked; publish it once with no indices before delivering credentials that point to it.

The full flow, with an Ed25519 and an ML-DSA-65 issuer, is exercised by `tests/eudi_issuance_e2e.rs`.
