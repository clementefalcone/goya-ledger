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

An operator needs an Ubuntu 24.04 host with a fixed public IP, TCP 8081 reachable from the other validators, and the `rust-bc` binary for its architecture.

1. Create the `goya` system user, `/var/lib/goya/data` (700) and the systemd unit from `install_validator` in the script.
2. Start the node once with only `STORAGE_BACKEND=rocksdb` and `STORAGE_PATH=/var/lib/goya/data`. It generates `signing_key_mldsa65.bin`; stop it.
3. Send the public key and the IP to Goya. The private key never leaves the host.
4. Join through the procedure above. Goya sends the snapshot and the shared environment values.

## Not yet covered

- Validator keys are files on disk (600, dedicated user, encrypted volume on AWS). Moving them to AWS KMS, which signs ML-DSA, needs a new signing provider.
- P2P traffic is authenticated by signed handshakes but not encrypted. Blocks are public; mutual TLS between validators is the next step.
- All four validators are operated by Goya.
