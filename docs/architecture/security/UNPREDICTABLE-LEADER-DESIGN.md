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
