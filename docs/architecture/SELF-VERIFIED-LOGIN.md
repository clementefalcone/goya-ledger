# Self-verified login

A person unlocks their phone with a fingerprint or face, enters any Saturnus app (Pet, Salud, AFP, Wallet), and the app knows it was that person's phone. This holds whichever Goya node the app talks to, after the phone is lost, and when the network has thousands of nodes. No node and no institution has to be trusted.

## Today

| Piece | Where it lives | Problem |
|---|---|---|
| Signing key (ML-DSA-65) | Phone, sealed by a passkey (WebAuthn PRF, user verification required); sealed copies in the DID's vault entries | None |
| Login challenge | Memory of one node (`/identity/auth/challenge`) | Lost on restart, not shared between nodes |
| Session token | JWT signed by that node's key, redeemable once on that node | The app trusts the node, not the phone; another node rejects it |
| Per-app subject (`pid:`) | HMAC with the node's `PAIRWISE_SECRET` | Another node with another secret gives the same person another subject |
| Pet, Salud users | DID derived on the app server from `GOYA_USER_KEY_SECRET` | Custodial: the app holds the person's key; one person ends up with several DIDs |
| Registry reads | `GET /store/identities/{did}` without proof | A lying or stale node can serve a wrong key |

A biometric never leaves the phone's secure chip. It unlocks the key on that device. It cannot prove to the network that the person is the same after a phone change, and it must never be stored on Goya (sensitive data that cannot be changed if leaked). Continuity therefore comes from keys, not from the biometric.

## Target

### 1. The app verifies the phone itself

1. The app creates a challenge: 32 random bytes, its origin, its audience, an expiry of at most 5 minutes.
2. It sends the person to Saturnus ID with that challenge. After the fingerprint, Saturnus ID signs `saturnus-id:login:v1:{audience}:{origin}:{challenge}:{expires_at}` with the person's key for that app (see per-app identity).
3. Saturnus ID returns the DID, the public key and the signature to the app.
4. The app checks that the DID is the SHA3-512 of the public key, that the signature verifies, that the challenge is its own, unused and unexpired, and that the registry on any node lists that DID as active with that public key.

No node signs anything and nothing is kept in node memory. `/identity/auth/challenge`, `/identity/auth/verify`, `/identity/auth/session/redeem` and `PAIRWISE_SECRET` retire once every app has moved.

### Per-app identity

Each app sees a different DID for the same person, so two apps cannot correlate them. The phone derives it, not the node:

- A 32-byte **identity root** is sealed in every vault copy next to the signing key. It is first derived from the signing key (HKDF-SHA256, info `saturnus-id identity root v1`), so copies sealed before roots existed yield it without migration. A key rotation carries the root over from the recovery kit's copy.
- The key for an app is `ML-DSA-65(HKDF-SHA256(root, "saturnus-id app key v1:{audience}"))`. Its DID is registered on Goya the first time the person enters that app, with a recovery commitment derived from the root the same way.
- Rotating the main key after a lost phone keeps the root, so every app still sees the same DID. The root travels to the new phone through a surviving device, the recovery kit, or (step 2) guardians.
- Revealing the main DID to an app is a separate, explicit choice made on the phone.

### 2. Recovery guardians

The person picks guardians (relative, notary, civil registry, another device) and a threshold, for example 2 of 3. The root is split with Shamir secret sharing (`identity::key_recovery::split`), and each guardian keeps one share sealed to their own DID. To recover, the person asks the guardians; each one verifies the person in its own way (in person, ID card against face) and releases its share. Goya never sees a biometric and never names a guardian: the person does.

### 3. Registry proofs

Nodes answer `GET /store/identities/{did}` with a Merkle proof against a state root signed by the validators, plus the block height. The app accepts the answer from any node without trusting it and requires a recent height, so a stale node cannot serve a key replaced after a lost phone.

### 4. Validators and full nodes

Thousands of nodes cannot all vote in BFT. A validator set (tens to hundreds, run by different organizations) orders and signs blocks. Full nodes (any number) replicate, verify every block and serve apps. Light clients (phones, app backends) verify registry proofs only.

## Order

1. Self-verified login with per-app identity in Saturnus ID; Pet first (its user key signs nothing), then Salud (consents signed by the phone, credentials delivered to the wallet over OID4VCI), then AFP and Wallet. Pet and Salud stop creating custodial DIDs; `GOYA_USER_KEY_SECRET` stays because it salts credentials already issued.
2. Guardians.
3. Registry proofs.
4. Validator and full node roles, once a second operator runs a node.
