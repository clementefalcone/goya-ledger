#!/usr/bin/env bash
set -euo pipefail

PROFILE="${AWS_TESTNET_PROFILE:?set AWS_TESTNET_PROFILE to the AWS CLI profile that pays for the testnet}"
ROOT="${TESTNET_ROOT:-${TMPDIR:-/tmp}/goya-testnet}"
TAG=goya-testnet
LIFETIME_MINUTES=4320
API_PORT=8080
P2P_PORT=8081
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH=(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=15)
NODES=(
  "v0 sa-east-1 arm64 t4g.micro"
  "v1 sa-east-1 amd64 t3.micro"
  "v2 us-east-1 arm64 t4g.micro"
  "v3 us-east-1 amd64 t3.micro"
  "v4 eu-central-1 arm64 t4g.micro"
  "v5 eu-central-1 amd64 t3.micro"
  "v6 sa-east-1 arm64 t4g.micro"
)

rust_target() { [ "$1" = arm64 ] && echo aarch64-unknown-linux-gnu || echo x86_64-unknown-linux-gnu; }
node_field() { echo "$1" | cut -d' ' -f"$2"; }
node_ids() { for node in "${NODES[@]}"; do node_field "$node" 1; done; }
regions() { for node in "${NODES[@]}"; do node_field "$node" 2; done | sort -u; }
node_spec() { printf '%s\n' "${NODES[@]}" | grep "^$1 "; }
aws_in() { aws --profile "$PROFILE" --region "$1" "${@:2}"; }
my_ip() { curl -fsS https://checkip.amazonaws.com | tr -d '\n'; }
public_ip() { cat "$ROOT/$1/ip"; }
joined() { local IFS=,; echo "$*"; }

security_group_id() {
  aws_in "$1" ec2 describe-security-groups --filters "Name=group-name,Values=$TAG" \
    --query 'SecurityGroups[0].GroupId' --output text
}

prepare_region() {
  local region=$1
  if ! aws_in "$region" ec2 describe-key-pairs --key-names "$TAG" >/dev/null 2>&1; then
    aws_in "$region" ec2 import-key-pair --key-name "$TAG" \
      --public-key-material "fileb://$SSH_KEY.pub" >/dev/null
  fi
  if [ "$(security_group_id "$region")" = "None" ]; then
    aws_in "$region" ec2 create-security-group --group-name "$TAG" \
      --description "Goya BFT testnet" \
      --tag-specifications "ResourceType=security-group,Tags=[{Key=project,Value=$TAG}]" >/dev/null
  fi
}

launch_node() {
  local spec id region arch type ami instance
  spec=$(node_spec "$1")
  id=$(node_field "$spec" 1); region=$(node_field "$spec" 2)
  arch=$(node_field "$spec" 3); type=$(node_field "$spec" 4)
  mkdir -p "$ROOT/$id"
  [ -s "$ROOT/$id/instance" ] && return 0
  ami=$(aws_in "$region" ssm get-parameter \
    --name "/aws/service/canonical/ubuntu/server/24.04/stable/current/$arch/hvm/ebs-gp3/ami-id" \
    --query Parameter.Value --output text)
  instance=$(aws_in "$region" ec2 run-instances --image-id "$ami" --instance-type "$type" \
    --key-name "$TAG" --security-group-ids "$(security_group_id "$region")" \
    --instance-initiated-shutdown-behavior terminate \
    --user-data "$(printf '#!/bin/bash\nshutdown -h +%s\n' "$LIFETIME_MINUTES")" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=project,Value=$TAG},{Key=Name,Value=$TAG-$id}]" \
      "ResourceType=volume,Tags=[{Key=project,Value=$TAG}]" \
    --query 'Instances[0].InstanceId' --output text)
  echo "$instance" > "$ROOT/$id/instance"
  echo "$region" > "$ROOT/$id/region"
}

record_public_ip() {
  local region instance
  region=$(cat "$ROOT/$1/region"); instance=$(cat "$ROOT/$1/instance")
  aws_in "$region" ec2 wait instance-running --instance-ids "$instance"
  aws_in "$region" ec2 describe-instances --instance-ids "$instance" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text > "$ROOT/$1/ip"
}

allow() {
  aws_in "$1" ec2 authorize-security-group-ingress --group-id "$(security_group_id "$1")" \
    --ip-permissions "IpProtocol=tcp,FromPort=$2,ToPort=$2,IpRanges=[{CidrIp=$3/32,Description=$TAG}]" \
    >/dev/null 2>&1 || aws_in "$1" ec2 describe-security-groups --group-ids "$(security_group_id "$1")" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`$2\`].IpRanges[].CidrIp" --output text \
    | grep -qw "$3/32"
}

open_firewall() {
  local operator region id
  operator=$(my_ip)
  for region in $(regions); do
    for port in 22 "$API_PORT" "$P2P_PORT"; do allow "$region" "$port" "$operator"; done
    for id in $(node_ids); do allow "$region" "$P2P_PORT" "$(public_ip "$id")"; done
  done
}

keygen() {
  local bin="${GOYA_KEYGEN_BIN:?set GOYA_KEYGEN_BIN to a native rust-bc binary}" port=19700 id dir pid
  [ -s "$ROOT/checkpoint.secret" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ROOT/checkpoint.secret"
  for id in $(node_ids); do
    dir="$ROOT/$id"
    mkdir -p "$dir/data"
    if [ ! -s "$dir/data/signing_key_mldsa65.bin" ]; then
      (cd "$dir" && exec env STORAGE_BACKEND=rocksdb STORAGE_PATH="$dir/data" SIGNING_ALGORITHM=ml-dsa-65 \
        BIND_ADDR=127.0.0.1 CHECKPOINT_HMAC_SECRET="$(cat "$ROOT/checkpoint.secret")" \
        "$bin" "$port" "$((port + 1))" > keygen.log 2>&1) &
      pid=$!
      for _ in $(seq 1 120); do
        [ -s "$dir/data/signing_key_mldsa65.bin" ] && break
        sleep 0.5
      done
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    [ -s "$dir/data/signing_key_mldsa65.bin" ] || { echo "keygen for $id produced no key" >&2; return 1; }
    python3 -c "import sys; print(open(sys.argv[1],'rb').read()[:1952].hex())" \
      "$dir/data/signing_key_mldsa65.bin" > "$dir/pk.hex"
    port=$((port + 2))
  done
}

node_env_file() {
  local id=$1 validators=() keys=() peers=() trusted=() other
  for other in $(node_ids); do
    validators+=("$other")
    keys+=("$other:$(cat "$ROOT/$other/pk.hex")")
    [ "$other" = "$id" ] && continue
    peers+=("$(public_ip "$other"):$P2P_PORT")
    trusted+=("$(cat "$ROOT/$other/pk.hex")")
  done
  cat <<EOF
STORAGE_BACKEND=rocksdb
STORAGE_PATH=/var/lib/goya/data
NETWORK_ID=$TAG
BIND_ADDR=0.0.0.0
RUST_BC_ENV=development
SIGNING_ALGORITHM=ml-dsa-65
RUST_LOG=info
CHECKPOINT_HMAC_SECRET=$(cat "$ROOT/checkpoint.secret")
P2P_EXTERNAL_ADDRESS=$(public_ip "$id"):$P2P_PORT
BFT_NODE_ID=$id
BFT_VALIDATORS=$(joined "${validators[@]}")
BFT_VALIDATOR_KEYS=$(joined "${keys[@]}")
TRUSTED_BLOCK_SIGNERS=$(joined "${trusted[@]}")
BOOTSTRAP_NODES=$(joined "${peers[@]}")
EOF
}

deploy_node() {
  local id=$1 spec arch binary host
  spec=$(node_spec "$id"); arch=$(node_field "$spec" 3)
  binary="target/$(rust_target "$arch")/release/rust-bc"
  host="ubuntu@$(public_ip "$id")"
  node_env_file "$id" > "$ROOT/$id/env"
  gzip -c "$binary" > "$ROOT/rust-bc-$arch.gz.tmp" && mv "$ROOT/rust-bc-$arch.gz.tmp" "$ROOT/rust-bc-$arch.gz"
  scp -q -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "$ROOT/rust-bc-$arch.gz" "$ROOT/$id/env" \
    "$ROOT/$id/data/signing_key_mldsa65.bin" "$host:"
  "${SSH[@]}" "$host" 'set -e
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin goya 2>/dev/null || id goya >/dev/null
    gunzip -f rust-bc-*.gz && sudo install -m 755 rust-bc-* /usr/local/bin/rust-bc
    sudo install -d -m 700 -o goya -g goya /var/lib/goya /var/lib/goya/data
    sudo install -m 600 -o goya -g goya signing_key_mldsa65.bin /var/lib/goya/data/
    sudo install -d -m 750 /etc/goya && sudo install -m 640 -g goya env /etc/goya/env
    rm -f rust-bc-* signing_key_mldsa65.bin env
    sudo tee /etc/systemd/system/goya.service >/dev/null <<UNIT
[Unit]
Description=Goya testnet validator
After=network-online.target
[Service]
User=goya
EnvironmentFile=/etc/goya/env
WorkingDirectory=/var/lib/goya
ExecStart=/usr/local/bin/rust-bc '"$API_PORT"' '"$P2P_PORT"'
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
    sudo systemctl daemon-reload && sudo systemctl enable --now goya'
}

launch() {
  local id region
  for region in $(regions); do prepare_region "$region"; done
  for id in $(node_ids); do launch_node "$id"; done
  for id in $(node_ids); do record_public_ip "$id"; done
  open_firewall
}

deploy() {
  local id
  keygen
  for id in $(node_ids); do
    until "${SSH[@]}" "ubuntu@$(public_ip "$id")" true 2>/dev/null; do sleep 5; done
    deploy_node "$id"
  done
}

remote_build() {
  local arch=$1 region=us-east-1 type=c7g.2xlarge ami builder ip host toolchain gate=true result
  [ "$arch" = amd64 ] && type=c7i.2xlarge
  [ "${REMOTE_GATE:-0}" = 1 ] && gate="cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo audit && cargo test --test crypto_boundary && cargo test --lib && cargo test --doc && cargo test --test bft_e2e --test bft_mldsa65_e2e && cargo test -p pqc_crypto_module --features acvp"
  toolchain=$(grep '^channel' rust-toolchain.toml | cut -d'"' -f2)
  prepare_region "$region"
  allow "$region" 22 "$(my_ip)"
  ami=$(aws_in "$region" ssm get-parameter \
    --name "/aws/service/canonical/ubuntu/server/24.04/stable/current/$arch/hvm/ebs-gp3/ami-id" \
    --query Parameter.Value --output text)
  builder=$(aws_in "$region" ec2 run-instances --image-id "$ami" --instance-type "$type" \
    --key-name "$TAG" --security-group-ids "$(security_group_id "$region")" \
    --instance-initiated-shutdown-behavior terminate \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=40,VolumeType=gp3,DeleteOnTermination=true}' \
    --user-data "$(printf '#!/bin/bash\nshutdown -h +180\n')" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=project,Value=$TAG},{Key=Name,Value=$TAG-builder-$arch}]" \
      "ResourceType=volume,Tags=[{Key=project,Value=$TAG}]" \
    --query 'Instances[0].InstanceId' --output text)
  aws_in "$region" ec2 wait instance-running --instance-ids "$builder"
  ip=$(aws_in "$region" ec2 describe-instances --instance-ids "$builder" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  host="ubuntu@$ip"
  until "${SSH[@]}" "$host" true 2>/dev/null; do sleep 5; done
  git ls-files -z | COPYFILE_DISABLE=1 xargs -0 tar czf - | "${SSH[@]}" "$host" 'mkdir -p src && tar xzf - -C src'
  "${SSH[@]}" "$host" "set -e
    cloud-init status --wait >/dev/null
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential cmake clang llvm-dev libclang-dev libssl-dev pkg-config perl protobuf-compiler >/dev/null
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal -c rustfmt -c clippy --default-toolchain $toolchain >/dev/null
    cd src && nohup bash -c 'export PATH=\$HOME/.cargo/bin:\$PATH; command -v cargo-audit >/dev/null || cargo install cargo-audit --locked >/dev/null 2>&1; ($gate) && cargo build --release --bin rust-bc; echo \$? > build.status' > build.log 2>&1 < /dev/null &"
  until "${SSH[@]}" "$host" 'test -s src/build.status' 2>/dev/null; do sleep 30; done
  result=$("${SSH[@]}" "$host" 'cat src/build.status')
  "${SSH[@]}" "$host" "grep -E '^test result|^error|warning: unused|Finished' src/build.log | tail -5"
  if [ "$result" = 0 ]; then
    mkdir -p "target/$(rust_target "$arch")/release"
    scp -q -i "$SSH_KEY" -o ServerAliveInterval=15 "${host}:src/target/release/rust-bc" "target/$(rust_target "$arch")/release/rust-bc"
  else
    mkdir -p "$ROOT"
    scp -q -i "$SSH_KEY" "${host}:src/build.log" "$ROOT/build-$arch.log"
    echo "build on $arch failed; log at $ROOT/build-$arch.log" >&2
  fi
  aws_in "$region" ec2 terminate-instances --instance-ids "$builder" >/dev/null
  [ "$result" = 0 ]
}

redeploy_binary() {
  local id spec arch host
  for id in $(node_ids); do
    spec=$(node_spec "$id"); arch=$(node_field "$spec" 3)
    host="ubuntu@$(public_ip "$id")"
    gzip -c "target/$(rust_target "$arch")/release/rust-bc" > "$ROOT/rust-bc-$arch.gz"
    scp -q -i "$SSH_KEY" -o ServerAliveInterval=15 "$ROOT/rust-bc-$arch.gz" "$host:"
    "${SSH[@]}" "$host" 'set -e; gunzip -f rust-bc-*.gz; sudo install -m 755 rust-bc-* /usr/local/bin/rust-bc; rm -f rust-bc-*
      sudo systemctl reset-failed goya; sudo systemctl restart goya'
  done
}

status() {
  local id
  for id in $(node_ids); do
    printf '%s %-15s ' "$id" "$(public_ip "$id")"
    if body=$(curl -fsS -m 5 "http://$(public_ip "$id"):$API_PORT/api/v1/store/blocks/latest" 2>/dev/null); then
      echo "$body" | python3 -c 'import json,sys; print("height", json.load(sys.stdin)["data"])'
    else
      echo unreachable
    fi
  done
}

teardown() {
  local region instances group
  for region in $(regions); do
    instances=$(aws_in "$region" ec2 describe-instances \
      --filters "Name=tag:project,Values=$TAG" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
      --query 'Reservations[].Instances[].InstanceId' --output text)
    if [ -n "$instances" ]; then
      aws_in "$region" ec2 terminate-instances --instance-ids $instances >/dev/null
      aws_in "$region" ec2 wait instance-terminated --instance-ids $instances
    fi
    group=$(security_group_id "$region")
    [ "$group" = "None" ] || aws_in "$region" ec2 delete-security-group --group-id "$group"
    aws_in "$region" ec2 delete-key-pair --key-name "$TAG"
    echo "$region clean"
  done
  rm -rf "$ROOT"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  "$@"
fi
