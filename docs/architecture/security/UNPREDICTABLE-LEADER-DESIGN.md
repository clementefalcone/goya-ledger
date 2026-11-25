# Design: Unpredictable Leader Election

Status: draft for decision. No code yet. Written after the leader-decapitation finding in [ADVERSARIAL-TESTNET-2026-11.md](ADVERSARIAL-TESTNET-2026-11.md).

## 1. The problem

Goya selects the BFT leader by `leader = validators[round % n]`. The schedule is public and fixed for all future rounds. An adversary that can isolate the current leader's P2P each round halts the chain while a quorum of honest nodes is up. Measured on the 7-node testnet: isolating 2 nodes (within the f = 2 budget) froze the chain at height 309 with 5/7 reachable; safety held (0 forks); it recovered on heal. Targeted leader isolation erases the crash-fault tolerance, because the one node that must drive each round is always the one removed.

## 2. Goal and the invariant

Goal: the leader of a round must be unknowable to an adversary until that leader's proposal is already propagating, so it cannot be pre-targeted.

Invariant, never traded: **safety (no two honest nodes commit different blocks at a height) must hold under every option here.** The 58 Lean no-fork theorems and the equivocation test must still pass. A liveness improvement that weakens safety is rejected outright.

Stance on cryptography: **align, do not invent.** Goya stands on NIST primitives (ML-DSA, ML-KEM, SHA3) because the community vetted them. Leader election must stand on a scheme that has survived public review, not a home-made one. One published post-quantum VRF (X-VRF) was broken after publication; a bespoke Goya primitive would invite the same. The novelty Goya can own is *integration and production hardening*, not new math.

## 3. The n matters more than the primitive

With a small validator set this reframes the whole fix. At n = 7, f = 2, quorum = 5:

- Isolating f + 1 = 3 validators stalls the chain by quorum loss, no matter who leads. That is the normal BFT bound.
- The decapitation attack stalled with only f = 2, *below* that bound, by exploiting predictability.
- An unpredictable leader removes that advantage: the attacker is forced back up from 2 to 3 (quorum loss). Real, but a one-node margin at n = 7.

The margin grows with n. At n = 100, f = 33: a predictable-leader attack needs ~1-2 targeted nodes; an unpredictable one forces ~34 (f + 1). So unpredictable leader election and a larger, independently-operated validator set (operational decentralization) are the same defense seen twice, and both are needed. At Goya's current n = 4 (mainnet) the cryptographic fix alone buys almost nothing; growing n is the larger lever. This design is worth executing, but its payoff scales with validator count.

## 4. Options surveyed

Each judged on: post-quantum, FIPS-compatible, maturity, fit for n = 4-7, cost.

| Option | Post-quantum | Maturity | Fit for small n | Cost |
|---|---|---|---|---|
| A. Secret leader election (SSLE), lattice-based (Qelect, RRC-SSLE) | Yes (RLWE/LWE) | Research, 2023-2025; not production-proven | Weak: anonymity set is only n; at n=7 the secret has 1-in-7 | High: homomorphic ops, multi-round, large messages |
| B. Post-quantum VRF sortition (LB-VRF, few-time VRF) | Yes (Module-SIS/LWE) | Some schemes broken (X-VRF); LB-VRF practical but new | Partial: unpredictable, but see §3 | Medium: ~5 KB proof, ms-scale verify, bigger consensus messages |
| C. TEE-assisted unpredictable leader (eBFT-style) | Inherits node crypto | Mature idea; needs trusted hardware | Good for permissioned n | Adds a hardware trust assumption (SGX/Nitro/TrustZone), against "trustless" |
| D. Leaderless / multi-proposer | Inherits node crypto | Mature designs exist | Good, but is a consensus rewrite | Highest: replaces HotStuff core |

Reading:

- **A (SSLE)** is the textbook answer for large committees, but its protection comes from a large anonymity set. At n = 7 the set is tiny, so its heavy cost buys little. Revisit when n is large.
- **B (lattice VRF sortition)** is the closest fit: it reuses lattice assumptions Goya already relies on, and gives true unpredictability. The risk is picking a scheme that gets broken — mitigated by choosing a reviewed construction (LB-VRF family, not X-VRF) and treating it as replaceable.
- **C (TEE)** is the cheapest to ship and strong for a permissioned set, but a trusted-hardware assumption contradicts the trust model and the post-quantum, no-special-hardware positioning. Record it as a fallback, not the headline.
- **D (leaderless)** removes the target entirely but means rewriting the consensus core — the opposite of the freeze rule, and high risk against the Lean proofs.

Provisional recommendation: **B, a reviewed lattice-based VRF sortition**, treated as a replaceable module, pursued *together with* raising n (phase 4). Not A (small n), not C (hardware trust), not D (rewrite). This is provisional until phase 0 confirms a concrete scheme fits.

## 5. What would change in Goya (minimal surface)

- `leader_for_round(round)` in `src/consensus/bft/round_manager.rs` becomes `leader_for_round(round, beacon)` where `beacon` is a per-round value no one can precompute.
- The chosen leader proves eligibility with a VRF proof carried in `BftProposal`; verifiers check the proof instead of recomputing `round % n`.
- Everything that currently calls `leader_for_round` (proposal admission, is-current-leader, timeout attribution) routes through the same function — one change point.
- The crypto primitive lives in `crates/pqc_crypto_module/` behind the existing boundary; `src/` never imports it directly.
- Unchanged: the vote/QC/commit machinery, the safety rule, the Lean model's safety core.

Open question for phase 0: what is the per-round beacon? It must be agreed by all honest nodes and unpredictable before the round. Candidates and their flaw during a stall (no new blocks) must be analysed; a beacon fixed during a stall re-opens the attack (see the rejected options in the adversarial report).

## 6. Phases

- **Phase 0 — spike (no production code).** Pick one concrete scheme. Prototype its keygen/eval/verify in isolation, measure proof size and verify time on the t4g/Graviton target, and settle the per-round beacon. Deliverable: a go/no-go with numbers. If nothing fits n = 4-7 at acceptable cost, say so and fall back to "grow n + network diversity" instead of shipping a weak cryptographic fix.
- **Phase 1 — primitive.** Implement the VRF in `pqc_crypto_module` with KATs, the crypto-boundary test, and the approved-mode guards. Gate in the cloud. No consensus change yet.
- **Phase 2 — integration.** Route `leader_for_round` through the beacon + VRF. Keep safety invariants; the Lean model and the equivocation test must still pass. Gate.
- **Phase 3 — re-attack and measure.** Rerun the decapitator against the upgraded testnet. Success criterion: the attacker can no longer halt the chain with f targeted isolations and is forced to f + 1 (quorum loss). Record before/after, as with the campaign.

Each phase ends with a gate and, from phase 2 on, a re-attack. Nothing merges to mainnet until phase 3 shows the measured improvement, and only then with all validators upgrading together.

## Phase 0 findings (go / no-go)

Run 2026-11-25. Research pass plus a code analysis of Goya's per-round state. A first-hand benchmark on Graviton was prepared but not run (see "measurement" below).

### Scheme reality

- The concrete fit is the LB-VRF family (lattice VRF, Module-SIS/LWE), which reuses the lattice assumptions Goya already depends on.
- The only Rust implementation (`zhenfeizhang/lb-vrf`) is research/prototype: it implements the **one-time** scheme; the **many-time** scheme is an open TODO in the repo ("decide which long-term signature scheme… implement scheme"). It carries no clear license and open tasks for zeroization and tests.
- LB-VRF is **k-time**: a key pair yields a fixed number of outputs (published variants: 8, 16, 128, 256). A consensus that runs forever would exhaust a key and needs a key-rotation / re-registration protocol layered on top — itself new, validator-set-coupled work.
- Published cost (authors' hardware, x86): 84-byte output, ~5 KB proof, ~3 ms evaluate, ~1 ms verify. The research is moving fast — ring VRFs (2026), Qelect SSLE (2025), key-homomorphic/aggregate VRFs (2024) — so a better-fitting, maintained scheme may arrive.

### The beacon is the real blocker

A VRF sortition still needs a per-round **beacon**: a value that is (a) agreed by all honest nodes, (b) unpredictable before the round, and (c) still produced **during a stall**, when no blocks commit. Analysis of Goya's code:

- The only per-round artifact that forms during a stall is the timeout certificate. In `round_manager.rs` it is built from `self.timeouts.values()` — each node's own subset of collected timeout votes. Different nodes hold different subsets, so the certificate's bytes, and any hash of them, **differ across nodes**. It is not canonical.
- A beacon derived from the last committed block is fixed during a stall, so it re-opens the attack exactly when it matters.
- Making the beacon work therefore needs either a canonicalized timeout certificate (deterministic quorum selection and ordering) or a threshold-randomness primitive — design work *beyond* the VRF, and the harder half.

### The margin at Goya's n

At n = 4-7 an unpredictable leader only forces the attacker from f targeted isolations up to f + 1 (quorum loss): a one-node margin at n = 7, and almost nothing at the mainnet n = 4. The payoff scales with n (see §3). Growing the independently-operated validator set is the larger near-term lever.

### Measurement

A benchmark of the prototype one-time scheme on a t4g (Graviton2, the mainnet hardware) was scripted but not executed; running external, unreviewed crypto on a fresh cloud node needs explicit approval. The go/no-go does not hinge on it, since the blockers below are independent of raw speed. If the VRF path is later taken, a first-hand Graviton benchmark is the first task of phase 1.

### Decision: no-go on shipping a lattice VRF sortition now

Three independent blockers, none about speed:

1. No production, many-time lattice VRF exists in Rust; the only implementation is prototype and one-time.
2. The per-round beacon that survives a stall is an unsolved design problem that likely needs another primitive or a consensus-level canonicalization.
3. At the current validator count the cryptographic fix buys a one-node margin; the larger lever is growing n.

Recommended instead, in order:

- **Near term:** pursue operational decentralization — more validators, run by independent operators across different providers/regions — which raises both the quorum-loss threshold and the cost of selectively partitioning the exact leader. This is the larger lever and needs no new cryptography.
- **Track:** the fast-moving post-quantum VRF / SSLE research, and revisit this path when n is large enough to justify it and a maintained many-time scheme exists.
- **Do not** ship a home-made VRF or a beacon hack presented as a fix; both would be the kind of half-measure this project's standard rejects.

This keeps the finding honest: the decapitation weakness is real and documented, the structural fix is a genuine research-grade project gated on a larger validator set, and the actionable near-term defense is decentralization, not a patch.
