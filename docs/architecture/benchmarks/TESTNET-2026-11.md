# Multi-Region Testnet, 2026-11-23

Seven ML-DSA-65 validators ran HotStuff BFT across three continents for one day. The network was deployed with `scripts/testnet/aws.sh`. Quorum is 5 of 7 (f = 2).

| Validator | Region | CPU |
|---|---|---|
| v0, v6 | sa-east-1 | ARM t4g.micro |
| v1 | sa-east-1 | x86 t3.micro |
| v2 | us-east-1 | ARM t4g.micro |
| v3 | us-east-1 | x86 t3.micro |
| v4 | eu-central-1 | ARM t4g.micro |
| v5 | eu-central-1 | x86 t3.micro |

Binaries were built, and the gate run, on Graviton and x86 cloud builders. The final gate passed 3076 lib tests and 32 BFT end-to-end tests.

## Fault tolerance

| Scenario | Result |
|---|---|
| ARM and x86 replicas | identical heights and hashes on all 7 |
| Two eu-central-1 validators down (5/7) | keeps deciding blocks |
| Three validators down (4/7) | halts without forking; resumes when they return |
| Partition 4/3 | neither side decides; no fork |
| Partition 5/2 | majority decides; minority stays on an exact prefix (same consensus hash); converges within 30 s of healing |
| Validator restarted with an empty ledger | rebuilds 166 blocks and 4055 identities in 4 min 16 s, then votes again |

## Byzantine validator

v1 acted as the attacker against the other six.

| Attack | Result |
|---|---|
| Forged timeouts claiming round 10^9 | ignored |
| Forged proposals from every leader | rejected |
| Forged votes for every validator | rejected |
| 30 MB votes and an 800 MB stream | dropped at the 10 MB message limit or the bytes/s limit; RSS stable on a 1 GB node |
| About 160 injected fake peers per node | commit latency unchanged at 3–4 s |

The quantum lab results are in [QUANTUM-LAB.md](../security/QUANTUM-LAB.md) §5.

## Load

The load generator was a c7g.xlarge in sa-east-1.

| Test | Result |
|---|---|
| 1080 req/s from one IP | 80 served, 2920 answered 429; consensus unaffected |
| 2000 signed ML-DSA registrations, 100 concurrent | 13.2 tx/s, p50 5.2 s, p95 17 s, 0 errors |
| 2000 more, 300 concurrent | 14.2 tx/s, p50 20.6 s, 0 errors |

Throughput is capped by the protocol, not the hardware: at most 50 transactions per block and about 3 s per intercontinental BFT round. Node CPU stayed near 28%.

## Defects found and fixed

| Commit | Defect |
|---|---|
| 829d2a7 | pqcrypto NEON code used the SHA3 `eor3` instruction, so the node got SIGILL on Graviton2 |
| 3eb01de | votes that arrived ahead of the replica's phase were dropped, so 5 of 7 validators stalled |
| 6956ab6 | broadcast connected serially with no timeout, so one silent peer stalled consensus for about 2 minutes per message |
| 1bff857 | a forged early vote could take a validator's slot (introduced by 3eb01de) |
| 6117421 | consensus awaited network sends, so injected fake peers slowed every round |
| 026f928 | partial TCP reads were scored as invalid messages, banning honest validators mid-proposal; the 10 MB limit applied per read |

## Open

- Peers announce their own address without authentication. They should authenticate with their validator key.
- The P2P ban is keyed by `ip:port`, so reconnecting evades it.
- The 50-transaction block cap sets the throughput ceiling.
- Catch-up arrives in batches with pauses between them.

Cost was about US$3: nodes for 8 hours, the builders and the load generator.
