#!/usr/bin/env bash
set -euo pipefail

binary=${1:?usage: operator-setup.sh <path-to-rust-bc> [api_port] [p2p_port]}
api_port=${2:-8080}
p2p_port=${3:-8081}

[ -s "$binary" ] || { echo "binary not found: $binary" >&2; exit 1; }

sudo useradd --system --no-create-home --shell /usr/sbin/nologin goya 2>/dev/null || id goya >/dev/null
sudo install -m 755 "$binary" /usr/local/bin/rust-bc
sudo install -d -m 700 -o goya -g goya /var/lib/goya /var/lib/goya/data
sudo install -d -m 750 /etc/goya
printf 'STORAGE_BACKEND=rocksdb\nSTORAGE_PATH=/var/lib/goya/data\n' \
  | sudo sh -c 'umask 077; cat > /etc/goya/env'
sudo chown root:goya /etc/goya/env
sudo chmod 640 /etc/goya/env

sudo tee /etc/systemd/system/goya.service >/dev/null <<UNIT
[Unit]
Description=Goya ledger validator
After=network-online.target
Wants=network-online.target
[Service]
User=goya
Group=goya
WorkingDirectory=/var/lib/goya
EnvironmentFile=/etc/goya/env
ExecStart=/usr/local/bin/rust-bc $api_port $p2p_port
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/goya
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload

if ! sudo test -s /var/lib/goya/data/signing_key_mldsa65.bin; then
  sudo systemctl start goya
  for _ in $(seq 1 60); do
    sudo test -s /var/lib/goya/data/signing_key_mldsa65.bin && break
    sleep 1
  done
  sudo systemctl stop goya
fi

pubkey=$(sudo head -c 1952 /var/lib/goya/data/signing_key_mldsa65.bin | xxd -p | tr -d '\n')
[ "${#pubkey}" -eq 3904 ] || { echo "validator key not generated" >&2; exit 1; }
arch=$(uname -m)
public_ip=$(curl -fsS -m 10 https://api.ipify.org 2>/dev/null || echo UNKNOWN)

cat <<REPORT

=== send these three values to Goya ===
public_key: $pubkey
public_ip:  $public_ip   (confirm this is your fixed, reachable IP)
arch:       $arch   (arm64 = aarch64, amd64 = x86_64)

TCP $p2p_port must be reachable from the other validators.
The node is installed and stopped. Do not start it until Goya has
sent the shared environment and added you to the validator set.
REPORT
