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

## Deep adversarial pass, 2026-11-25

A second, instrumented pass ran on a fresh 7-node testnet (no Byzantine validator; faults only) to measure the open items and probe attacks the first campaign did not cover.

### Write failures within budget were an ack artifact, not lost data

Instrumented chaos (15 min, one honest fault at a time, 4 writers) recorded the DID of every failed write and checked afterwards whether it had committed:

| Metric | Value |
|---|---|
| Acknowledged writes | 539 |
| Failed writes (HTTP) | 41 |
| Of those, committed anyway | 40 |
| Truly lost | 1 (of 580 = 0.17%) |
| Forks | 0 |

The "46% failure" from the first campaign was writes whose HTTP ack did not arrive within 30 s while the write committed. It measured the ack, not the commit. This run is not a clean comparison to the 46% figure — it had no Byzantine validator and only one fault at a time — but the instrumentation finding stands: a failed ack is not a lost write. Fixes `314a007`, `f3e4600`, `718ec77` also landed from this pass (hex signatures, state-request cap, unadmitted buffer cap).

### Consensus-message flood (timeout bomb): real in code, defended in practice

`BftVote` and `BftTimeout` are forwarded to an unbounded channel with no signature check and no admitted-source check; processing one timeout forces up to ~12 ML-DSA verifications (its vote, a timeout certificate, and a high QC). A flood should pin CPU, grow the queue, and starve real consensus.

Attempted: a 20-IP swarm (`swarm-bomb`) and a paced single IP. Result: v0 held at ≤18% CPU (≤45% paced), RSS stable at ~100 MB, chain advancing, all nodes in lockstep. The per-IP limits from the first campaign (16 connections, 100 msg/s, 10 MB/s) plus TCP read backpressure (~2–6 msg/s per connection) throttled the attack below the level where verification amplification bites. Not disproven: a large botnet (hundreds of distinct IPs) multiplies the per-IP throughput, and the unbounded channel is a latent memory risk. Fix still warranted as defense in depth: admit-check consensus messages before queueing and bound the channel.

### Leader decapitation halts liveness within the fault budget

Leader selection is round-robin and fully predictable: `leader = validators[round % n]`. An adversary that isolates (iptables DROP on 8081) the current leader each round halts the chain while a quorum of honest nodes is up.

| Metric | Value |
|---|---|
| Nodes isolated at a time | 2 (within f = 2) |
| Nodes reachable | 5 of 7 (quorum available) |
| Chain | frozen at height 309 |
| Forks | 0 (safety held) |
| On heal | advanced to 310, consistent hash |

Two *targeted* crashes defeat liveness where two *arbitrary* crashes would not: targeted leader isolation effectively erases the crash-fault tolerance, because the one node that must drive each round is always the one removed. It is self-reinforcing — once blocks stop, view-change backoff escalates to 30 s, slowing rounds and making the attacker's timing trivial. Isolation here used root control of the nodes; a real attacker needs an on-path network position (ISP, BGP, or a host near a validator) to drop the leader's P2P in real time, and the predictable schedule makes that cheap once the position exists. Independent validators across providers (operational decentralization) raise the cost of selectively partitioning the exact leader.

The structural fix is unpredictable leader election (VRF sortition), so the adversary cannot know which node to target before its proposal is already propagating. This is a consensus-core change and needs a VRF primitive the module does not yet have.

## Open

- An honest validator still crossed the 100 msg/s limit 41 times in one run, without being banned (message kind now logged for the next pass).
- Consensus messages (`BftVote`, `BftTimeout`) are queued unauthenticated to an unbounded channel; defended in practice by per-IP limits, not by design.
- Leader rotation is predictable, enabling targeted leader isolation; structural fix is VRF sortition.
- A validator that is admitted can repeat `StateRequest` up to 5/s per IP; still unbounded in total across a session.
- Validators are bounded by 64 connections per IP and do not count toward the global cap. A compromised validator could use that room.
