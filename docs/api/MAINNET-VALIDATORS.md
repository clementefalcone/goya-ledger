# Mainnet Validators

Mainnet runs HotStuff BFT with four ML-DSA-65 validators. Quorum is 3 of 4, so the network keeps deciding blocks with any one validator down, and no single validator can forge a block.

| Id | Host | Provider |
|---|---|---|
| v0 | 162.254.32.12 | VPS (also serves the local apps on 127.0.0.1:8080) |
| v1 | Elastic IP | AWS sa-east-1, t4g.micro |
| v2 | Elastic IP | AWS us-east-1, t4g.micro |
| v3 | Elastic IP | AWS eu-central-1, t4g.micro |

All four are operated by Goya today.

## Script

`scripts/mainnet/validators.sh` drives everything. It needs `AWS_MAINNET_PROFILE` and `MAINNET_ROOT`, a private directory that keeps each validator's instance id, IP and public key.

| Command | Effect |
|---|---|
| `provision` | Launches v1–v3 with encrypted disks, termination protection and Elastic IPs, opens P2P only between validators, installs the binary and generates each validator key on its own host |
| `cutover` | Stops v0, snapshots its ledger without keys, loads the snapshot on v1–v3, writes the BFT environment on all four and starts them. Backups of v0 go to `/home/admin/*before-bft-<stamp>*` |
| `rollback <stamp>` | Restores v0 from those backups as a single node and stops v1–v3 |
| `heights` | Prints `chain/info` from each validator |
| `ops` | Creates the backup bucket, IAM permissions, alarms and the cron jobs below |

Validators start from a snapshot, not a replay from genesis: early mainnet state was written before every change went through a block, so a replay diverges.

## Monitoring

Every validator posts a `Goya/Healthy` metric each minute while its API answers. A CloudWatch alarm per validator (`goya-<id>-down`, us-east-1) emails `ALERT_EMAIL` after five minutes without it, and again when it recovers.

## Backups

The bucket `goya-mainnet-backups-<account>` (us-east-1, versioned, private) holds:

- `keys/<id>-signing_key_mldsa65.bin.age`: each validator key, uploaded once.
- `ledger/v1-<time>.tar.gz.age`: the ledger, daily at 03:20 UTC from v1, kept 30 days. v1 stops for a few seconds; quorum holds with the other three.

Everything is encrypted with [age](https://age-encryption.org) to a recipient whose private key lives only with the operator (`~/.goya-backup/age.key`). Keep a copy of that key offline: without it the backups cannot be read.

Restore a ledger onto a stopped validator:

```bash
aws s3 cp s3://goya-mainnet-backups-<account>/ledger/<file>.age - | age -d -i ~/.goya-backup/age.key | ssh <host> 'sudo tar xzf - -C /var/lib/goya && sudo chown -R goya:goya /var/lib/goya'
```

## Changing the validator set

The set is static configuration (`BFT_VALIDATORS`, `BFT_VALIDATOR_KEYS`, `TRUSTED_BLOCK_SIGNERS`, `BOOTSTRAP_NODES`), read at startup. Every validator must run the same set, so a change is a coordinated restart:

1. The new validator generates its key on its own machine and sends only the public key (the first 1952 bytes of `signing_key_mldsa65.bin`, hex).
2. Stop all validators. A halted BFT network does not fork.
3. Load the latest ledger snapshot on the new validator.
4. Write the new set on every validator and start them all.
5. Check `heights` and submit one write.

Removing a validator is the same with its entry deleted. Keep at least four.

## Joining as an independent operator

This is the lever for operational decentralization: a validator run by a
different operator, on a different provider and network, raises the real cost
of selectively partitioning the current leader (the decapitation weakness in
`docs/architecture/security/ADVERSARIAL-TESTNET-2026-11.md`). More nodes under
the same operator and account do not.

The operator needs an Ubuntu 24.04 host with a fixed public IP, TCP 8081
reachable from the other validators, and the `rust-bc` binary for its
architecture (Goya builds it in the cloud and hands it over; the operator does
not build or receive source).

Operator side:

1. Run `scripts/mainnet/operator-setup.sh <rust-bc> [api_port] [p2p_port]` on
   the host. It creates the `goya` user, the hardened systemd unit, the data
   directory, generates `signing_key_mldsa65.bin`, leaves the node stopped, and
   prints the public key, public IP and architecture to send to Goya. The
   private key never leaves the host.
2. Send those three values to Goya. Do not start the node yet.

Goya side:

3. Send the operator the shared secret values (`CHECKPOINT_HMAC_SECRET`,
   `PAIRWISE_SECRET`, `NOTA_ISSUER_DID`) and the latest ledger snapshot; the
   operator appends the secrets to `/etc/goya/env` and loads the snapshot into
   `/var/lib/goya/data`.
4. Add the new `{id, ip, public_key}` to `BFT_VALIDATORS`,
   `BFT_VALIDATOR_KEYS`, `TRUSTED_BLOCK_SIGNERS` and `BOOTSTRAP_NODES` on every
   validator, write the operator's full `bft_env` (set plus its own
   `P2P_EXTERNAL_ADDRESS` and `BFT_NODE_ID`), then do the coordinated restart
   above (a halted BFT network does not fork). Keep at least four.

Tooling gap (do before the first external operator): `validators.sh` assumes
every non-VPS node lives in Goya's AWS account — `address_of`, `key_of` and
`host_of` resolve through AWS APIs, so an arbitrary external IP is not
representable. Adding an external validator today is the manual env edit plus
coordinated restart above. The minimal fix is to let the node set carry a
static external entry (`id ip arch public_key`) that bypasses the AWS lookups.

## Post-quantum TLS (mesh encryption)

All validator traffic rides a hybrid post-quantum TLS channel
(X25519+ML-KEM-768 key exchange, `TLS_PQC_KEM=true`). Certificates are
issued by `scripts/mainnet/mesh-ca.sh`: a private CA plus one EC cert per
validator carrying its public IP as an IP SAN (the P2P client verifies peers
by IP). The post-quantum protection is in the key exchange; the classical
certificate signature only authenticates a live handshake.

The same `TLS_CERT_PATH`/`TLS_KEY_PATH` enable TLS on both the P2P listener
and the API, so the API serves **HTTPS** once TLS is on — health checks and
`heights` try `https -k` first. `TLS_MUTUAL` is false: the channel is
encrypted and server-authenticated against the CA, while validator identity
stays enforced by the ML-DSA-signed `Version` handshake and admitted-source
checks. Setting `TLS_MUTUAL=true` would also require a client certificate on
the API and lock out plain callers, so it is left off.

Certs and key live in `/var/lib/goya/tls` (owned by the `goya` user so the
service can read them; `/etc/goya` is not traversable by that user). To roll
the mesh off, remove the `TLS_*` lines from each `env` and restart.

## Not yet covered

- Validator keys are files on disk (600, dedicated user, encrypted volume on AWS). Moving them to AWS KMS, which signs ML-DSA, needs a new signing provider.
- The TLS channel is encrypted and server-authenticated but not certificate-mutual; decoupling P2P TLS from the API would allow full mutual-cert TLS on the mesh without locking the API.
- All four validators are operated by Goya; the section above is the path to the first independent one.
