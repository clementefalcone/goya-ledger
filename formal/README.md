# formal

Lean 4 models of selected Goya properties. They are models, not proofs about the Rust code that runs in production, and they do not prove that Goya is secure against quantum adversaries.

All 48 theorems are checked by the Lean kernel and depend only on Lean's standard axioms (`propext`, `Classical.choice`, `Quot.sound`) or on none. There is no `sorry`, no `axiom` and no `native_decide`. Hashing and sampling are `opaque` constants.

## What is proven

| File | Proves | Scope |
|---|---|---|
| `BftSafety.lean` | Two quorums of at least 2f+1 out of 3f+1 validators overlap in at least f+1 nodes, so they share an honest node | Arithmetic on quorum sizes. Not a proof of the HotStuff protocol or of `src/consensus/bft/quorum.rs` |
| `FipsStateMachine.lean` | Reachability and absorbing states of the crypto module state machine | Abstract model of the state machine |
| `QuarantineCorrectness.lean` | Which algorithm sets are quarantined, checked on concrete cases | Abstract model of the quarantine rule |
| `Lattice/MlDsa.lean` | Linearity of the matrix product, and `A·z − c·t = A·y − c·s₂` for a response `z = y + c·s₁` with `t = A·s₁ + s₂` | Ring `Z_q[X]/(X²⁵⁶ + 1)` with q = 8380417 |
| `Lattice/SecurityGame.lean` | A forgery that passes the model's `verify` is a SelfTargetMSIS solution in the model | Holds by definition, see limitations |
| `Lattice/RejectionSampling.lean` | With the ML-DSA-65 parameters, shifting an accepted response by at most β stays inside the masking range, injectively | Integer arithmetic on the parameters only |

## Limitations of the ML-DSA model

- No rounding (`HighBits`, `LowBits`), no hints and no compression of `t`. Because of that, `sign` hashes `A·y` while `verify` recomputes `A·y − c·s₂`, so an honest signature does not verify in this model unless `s₂ = 0`. Real ML-DSA closes that gap with `HighBits`. No theorem here claims that honest signatures verify.
- No infinity-norm checks in `verify` and no shortness condition in SelfTargetMSIS, so the forgery-to-SelfTargetMSIS step is a restatement of the definitions, not a reduction.
- No probabilities, distributions or quantum adversary.

## What is not proven here

- That Module-LWE or Module-SIS are hard. That is a standard conjecture, not a theorem, and this development does not state it.
- EUF-CMA security of ML-DSA in the quantum random oracle model. Mechanized proofs of the Fiat-Shamir with aborts argument exist in EasyCrypt (Barbosa et al., CRYPTO 2023) and are the reference to cite.
- That the PQClean code linked through the `pqcrypto-*` crates in `crates/pqc_crypto_module` matches FIPS 204. Its evidence is the NIST ACVP test vectors, which are tests, not proofs.
- Constant-time behaviour of any implementation.
- Any property of the Rust code in `src/`.

## Build

```bash
lake exe cache get
lake build
```

To list the axioms a theorem depends on, run `#print axioms GoyaFormal.<theorem>` in a file that imports `Formal`.
