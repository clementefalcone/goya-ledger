# formal

Lean 4 models of selected Goya properties. They are models, not proofs about the Rust code that runs in production, and they do not prove that Goya is secure against quantum adversaries.

All 58 theorems are checked by the Lean kernel and depend only on Lean's standard axioms (`propext`, `Classical.choice`, `Quot.sound`) or on none. There is no `sorry`, no `axiom` and no `native_decide`. Hashing and sampling are `opaque` constants.

## What is proven

| File | Proves | Scope |
|---|---|---|
| `HotStuffSafety.lean` | `HotStuff.Execution.no_fork`: with n = 3f + 1 validators and at most f faulty, two blocks that each gather a CommitQC never conflict | Model of the protocol, see below. Not a proof of the Rust code |
| `FipsStateMachine.lean` | Reachability and absorbing states of the crypto module state machine | Abstract model of the state machine |
| `QuarantineCorrectness.lean` | Which algorithm sets are quarantined, checked on concrete cases | Abstract model of the quarantine rule |
| `Lattice/MlDsa.lean` | Linearity of the matrix product, and `A·z − c·t = A·y − c·s₂` for a response `z = y + c·s₁` with `t = A·s₁ + s₂` | Ring `Z_q[X]/(X²⁵⁶ + 1)` with q = 8380417 |
| `Lattice/SecurityGame.lean` | A forgery that passes the model's `verify` is a SelfTargetMSIS solution in the model | Holds by definition, see limitations |
| `Lattice/RejectionSampling.lean` | With the ML-DSA-65 parameters, shifting an accepted response by at most β stays inside the masking range, injectively | Integer arithmetic on the parameters only |

## HotStuff no-fork (`Formal/HotStuffSafety.lean`)

**Theorem** `HotStuff.Execution.no_fork`: with `n = 3f + 1` validators and at most `f` faulty ones, two blocks that each gather a CommitQC are never in conflict. One is an ancestor of the other.

The proof uses only Lean's standard axioms (`propext`, `Quot.sound`). `fourNodesDecideOneBlock` builds a concrete execution (4 nodes, one decided block), so the assumptions are satisfiable.

### What the model assumes, and where the code enforces it

Faulty validators may vote for anything. Each assumption below constrains honest validators only.

| Assumption in `Execution` | Code that enforces it |
|---|---|
| `Certified`: a QC holds `2f + 1` distinct validator votes | `QuorumValidator::validate_qc` and `quorum_threshold` (`src/consensus/bft/quorum.rs`) |
| `precommitOnce`, `commitOnce`: one block per round and phase | `BftRound` stores a single `block_hash` per round. Its collectors are bound to that hash (`round.rs`). `RoundManager` only moves to higher rounds (`on_timeout`, `advance_after_decide`) |
| `precommitNeedsPrepareQc`, `commitNeedsPrecommitQc`: vote in the next phase only after seeing the QC of the previous one | `handle_action`, `PhaseComplete` branch (`src/consensus/controller.rs`) |
| `prepareIsSafe`: every Prepare vote, the leader's included, passes `safeToVote` | `SafetyState::safe_to_vote` (`safety.rs`), called for `Proposal` and `StartAsLeader` in `RoundManager::process_event` |
| `safeToVote`: extends the lock, or `lock.round < justify.round < round` and extends the justify block | Rules 2b and 2c of `safe_to_vote` |
| `lockIsPrecommitQc`: the lock is a PreCommitQC from an earlier round | `update_locked_qc` on `PhaseComplete(PreCommit)`. Votes are only processed for the current round |
| `justifyIsQc`: the justify QC is a valid QC | `validate_received_qc` before `safe_to_vote`. The leader uses its own `high_qc` |
| `lockCoversCommit`: after a Commit vote in round `r`, the lock round is at least `r` | The lock is updated before the Commit vote is sent, and `update_locked_qc` never lowers it |
| `Ancestry` is a preorder | `ChainAncestryChecker::is_ancestor` walks `parent_hash` links and fails closed. A proposal joins the index (`index_proposal`) only after its body hashes to the proposed hash (`run_bft_loop`) |
| Decided blocks are the ledger | The leader builds its proposal with `MiningService::build_block` without writing it. Every node writes a block only on `Decide` (`commit_block`) |

### Outside the model

- Signatures cannot be forged, and block hashes do not collide (SHA-256, ML-DSA-65).
- Liveness: the theorem says nothing about progress. In the code, a leader whose `high_qc` block is still undecided and sits on the last decided block proposes that block again (`reproposable_block` in `controller.rs`), so validators locked on it can vote. A round-manager test checks that four locked validators decide it. A locked validator whose lock is newer than the leader's `high_qc` waits until it becomes leader itself.

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

The gauntlet (T0) fails if any file contains `sorry`, `admit` or `axiom`.

To list the axioms a theorem depends on, run `#print axioms GoyaFormal.<theorem>` in a file that imports `Formal`.
