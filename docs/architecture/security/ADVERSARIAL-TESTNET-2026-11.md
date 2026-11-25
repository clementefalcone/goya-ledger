# Adversarial Testnet Campaign, 2026-11-24/25

Seven ML-DSA-65 validators ran HotStuff BFT across sa-east-1, us-east-1 and eu-central-1, deployed with `scripts/testnet/aws.sh`. Quorum is 5 of 7 (f = 2). v1 was a Byzantine validator: a Python process holding a real validator key, speaking the wire protocol directly. Every binary was built, and the full gate run, on cloud builders.

"Before" is the first measurement of each attack, taken before the fix it led to; the chaos baselines therefore already include the earlier campaign fixes. "After" is the final tree (`9d40b49`). All runs used the same seven machines and the same tools.

## Results

| Attack | Before | After |
|---|---|---|
| Equivocation: v1 proposes block A to everyone, then block B to three victims | v4, v5, v6 stored B while the quorum certified A; the chain halted at height 2 | 2 equivocations, 0 forks; victims commit the certified block |
| One IP opens 150 silent connections to v0 | 178 honest connections refused | v0 serves normally; 0 of 150 silent connections stay open |
| `StateRequest` from a non-validator IP (amplification) | full blocks served | 0 bytes |
| Chaos within budget: v1 Byzantine plus one honest fault at a time, 15 min, 4 writers | 0 acknowledged writes, 122 failed | 107 acknowledged, 91 failed, p50 4.7 s, p95 22 s |
| Chaos over budget: up to two honest faults plus v1, 20 min, 4 writers | 20 acknowledged, 157 failed | 186 acknowledged, 111 failed, p50 4.3 s, p95 23 s |
| 20 IPs × 40 connections against v0, 15 min | v0 wrote 0 of 15 and stuck at height 97; the others reached 122 | v0 wrote 15 of 15 at about 2 s; it kept deciding (21 blocks in 8 min); 95,492 swarm connections refused by the per-IP cap |
| Forks and acknowledged writes lost, all runs | 0 | 0 |

Chaos faults were partitions (iptables), 800 ms ± 400 ms delay with 20% loss (netem), a 240 s clock jump, and `kill -9`. Each run ended by healing all faults and checking every block on every honest node and every acknowledged write on every honest node.

## Fuzzing

cargo-fuzz on a c7i builder, 0 crashes:

| Target | Runs |
|---|---|
| p2p_message | 11.9 M |
| block_parser | 15.0 M |
| gossip | 25.7 M |
| signature | 70.3 M |
| mldsa65_verify | 1.48 M |

## Defects found and fixed

| Commit | Defect |
|---|---|
| 9c7fe21 | a replica committed the proposal it had stored, not the block the quorum certified, so an equivocating leader forked victims |
| 113e5d7 | silent connections were never closed and one IP could take every slot |
| 58cfca2 | any IP could request full state, an amplification vector |
| 00d148b | the 16-per-IP cap from 113e5d7 refused honest validators' broadcast bursts, and a multi-IP swarm filled the global slots and cut v0 off from its peers |
| c374c30 | a proposal that arrived before its timeout certificate was discarded, so rounds died and the chain stalled within the fault budget |
| 9ddce3d | a stale timeout sent to help a lagging peer looked lagging itself, so validators answered each other forever (about 330 broadcasts in 2 s), tripped the message limit and banned each other |
| 9d40b49 | admission for state sync lived in memory; after peers restarted, a lagging validator was refused forever (introduced by 58cfca2) |
| 3b56543, f71397a | crypto self-test suites raced on one process-wide flag and failed the gate intermittently; 30 consecutive runs pass |
| 2c9c244 | the fuzz crate did not build; P2P messages had no fuzz target |

Two of these defects were regressions introduced earlier in the same campaign (`113e5d7` and `58cfca2`). The chaos runs caught both before release. The ping-pong in `9ddce3d` dates from 09fe418 and runs on mainnet today; the mainnet VPS log shows 0 bans and no broadcast bursts over the last 7 days.

Every commit was checked on a cloud builder: clippy with `-D warnings` and 3087–3089 lib tests. The final tree also passed fmt, doc tests, `crypto_boundary`, `bft_e2e` (21), `bft_mldsa65_e2e` (11) and the `pqc_crypto_module` suites with `acvp`.

## Open

- Within the fault budget, 46% of writes still fail. The writer picks any honest node, including the one under fault, and waits 30 s for inclusion while view-change backoff can reach 30 s. The split between these two causes was not measured.
- An honest validator still crossed the 100 msg/s limit 41 times in one run, without being banned.
- BFT timeout messages are about 130 KB, because signatures inside them serialize as JSON number arrays.
- A validator that is admitted can repeat `StateRequest` without limit.
- Validators are bounded by 64 connections per IP and do not count toward the global cap. A compromised validator could use that room.
