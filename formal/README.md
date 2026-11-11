# formal

Lean 4 proofs, checked by `lake build` (no Mathlib). The gauntlet (T0) fails if any file contains `sorry`, `admit` or `axiom`.

```bash
cd formal && lake build
```

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
- Liveness: the theorem says nothing about progress. A lock on a block that never reaches a CommitQC stalls the validators that hold it, because leaders always build on the last decided block.

## Other proofs

- `FipsStateMachine.lean`: transitions of the FIPS self-test state machine (`crates/pqc_crypto_module`).
- `QuarantineCorrectness.lean`: classification of classical versus post-quantum algorithms.
