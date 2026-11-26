#!/usr/bin/env bash
set -euo pipefail

export AWS_TESTNET_PROFILE="${AWS_MAINNET_PROFILE:?set AWS_MAINNET_PROFILE to the AWS CLI profile that pays for the validators}"
source "$(dirname "$0")/../testnet/aws.sh"

ROOT="${MAINNET_ROOT:?set MAINNET_ROOT to a private directory for validator state}"
TAG=goya-mainnet
VPS_HOST=admin@162.254.32.12
VPS_IP=162.254.32.12
VPS_DATA=/var/lib/goya-node
VPS_ENV=/etc/goya-node/env
NODES=(
  "v1 sa-east-1 arm64 t4g.micro"
  "v2 us-east-1 arm64 t4g.micro"
  "v3 eu-central-1 arm64 t4g.micro"
)
SHARED_SECRETS="CHECKPOINT_HMAC_SECRET|PAIRWISE_SECRET|NOTA_ISSUER_DID"

host_of() { echo "ubuntu@$(public_ip "$1")"; }
write_private() { echo "sudo sh -c 'umask 077; cat > $1' && sudo chown root:goya $1 && sudo chmod 640 $1"; }

launch_validator() {
  local spec id region arch type ami instance allocation
  spec=$(node_spec "$1")
  id=$(node_field "$spec" 1); region=$(node_field "$spec" 2)
  arch=$(node_field "$spec" 3); type=$(node_field "$spec" 4)
  mkdir -p "$ROOT/$id"
  if [ ! -s "$ROOT/$id/instance" ]; then
    ami=$(aws_in "$region" ssm get-parameter \
      --name "/aws/service/canonical/ubuntu/server/24.04/stable/current/$arch/hvm/ebs-gp3/ami-id" \
      --query Parameter.Value --output text)
    instance=$(aws_in "$region" ec2 run-instances --image-id "$ami" --instance-type "$type" \
      --key-name "$TAG" --security-group-ids "$(security_group_id "$region")" \
      --disable-api-termination \
      --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}' \
      --tag-specifications "ResourceType=instance,Tags=[{Key=project,Value=$TAG},{Key=Name,Value=$TAG-$id}]" \
        "ResourceType=volume,Tags=[{Key=project,Value=$TAG}]" \
      --query 'Instances[0].InstanceId' --output text)
    echo "$instance" > "$ROOT/$id/instance"
    echo "$region" > "$ROOT/$id/region"
  fi
  instance=$(cat "$ROOT/$id/instance")
  aws_in "$region" ec2 wait instance-running --instance-ids "$instance"
  if [ ! -s "$ROOT/$id/ip" ]; then
    allocation=$(aws_in "$region" ec2 allocate-address --domain vpc \
      --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=project,Value=$TAG},{Key=Name,Value=$TAG-$id}]" \
      --query AllocationId --output text)
    aws_in "$region" ec2 associate-address --instance-id "$instance" --allocation-id "$allocation" >/dev/null
    aws_in "$region" ec2 describe-addresses --allocation-ids "$allocation" \
      --query 'Addresses[0].PublicIp' --output text > "$ROOT/$id/ip"
  fi
}

open_validator_firewall() {
  local region id other
  for id in $(node_ids); do
    region=$(cat "$ROOT/$id/region")
    allow "$region" 22 "$(my_ip)"
    allow "$region" "$P2P_PORT" "$VPS_IP"
    for other in $(node_ids); do allow "$region" "$P2P_PORT" "$(public_ip "$other")"; done
  done
  for id in $(node_ids); do
    "${SSH[@]}" "$VPS_HOST" "sudo ufw allow proto tcp from $(public_ip "$id") to any port $P2P_PORT comment goya-$id >/dev/null"
  done
}

install_validator() {
  local id=$1 spec arch host
  spec=$(node_spec "$id"); arch=$(node_field "$spec" 3)
  host=$(host_of "$id")
  until "${SSH[@]}" "$host" true 2>/dev/null; do sleep 5; done
  gzip -c "target/$(rust_target "$arch")/release/rust-bc" > "$ROOT/rust-bc-$arch.gz"
  scp -q -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "$ROOT/rust-bc-$arch.gz" "$host:"
  "${SSH[@]}" "$host" 'set -e
    cloud-init status --wait >/dev/null
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin goya 2>/dev/null || id goya >/dev/null
    gunzip -f rust-bc-*.gz && sudo install -m 755 rust-bc-* /usr/local/bin/rust-bc && rm -f rust-bc-*
    sudo install -d -m 700 -o goya -g goya /var/lib/goya /var/lib/goya/data
    sudo install -d -m 750 /etc/goya
    printf "STORAGE_BACKEND=rocksdb\nSTORAGE_PATH=/var/lib/goya/data\n" | '"$(write_private /etc/goya/env)"'
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
ExecStart=/usr/local/bin/rust-bc '"$API_PORT"' '"$P2P_PORT"'
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
      for _ in $(seq 1 60); do sudo test -s /var/lib/goya/data/signing_key_mldsa65.bin && break; sleep 1; done
      sudo systemctl stop goya
    fi
    sudo head -c 1952 /var/lib/goya/data/signing_key_mldsa65.bin | xxd -p | tr -d "\n"' > "$ROOT/$id/pk.hex"
  [ "$(wc -c < "$ROOT/$id/pk.hex")" -eq 3904 ] || { echo "no validator key on $id" >&2; return 1; }
}

record_vps_key() {
  "${SSH[@]}" "$VPS_HOST" "sudo head -c 1952 $VPS_DATA/data/signing_key_mldsa65.bin | xxd -p | tr -d '\n'" > "$ROOT/v0.pk.hex"
  [ "$(wc -c < "$ROOT/v0.pk.hex")" -eq 3904 ]
}

address_of() { [ "$1" = v0 ] && echo "$VPS_IP:$P2P_PORT" || echo "$(public_ip "$1"):$P2P_PORT"; }
key_of() { [ "$1" = v0 ] && cat "$ROOT/v0.pk.hex" || cat "$ROOT/$1/pk.hex"; }

bft_env() {
  local id=$1 validators=() keys=() peers=() trusted=() other
  for other in v0 $(node_ids); do
    validators+=("$other")
    keys+=("$other:$(key_of "$other")")
    [ "$other" = "$id" ] && continue
    peers+=("$(address_of "$other")")
    trusted+=("$(key_of "$other")")
  done
  cat <<EOF
P2P_EXTERNAL_ADDRESS=$(address_of "$id")
BFT_NODE_ID=$id
BFT_VALIDATORS=$(joined "${validators[@]}")
BFT_VALIDATOR_KEYS=$(joined "${keys[@]}")
TRUSTED_BLOCK_SIGNERS=$(joined "${trusted[@]}")
BOOTSTRAP_NODES=$(joined "${peers[@]}")
EOF
}

write_validator_env() {
  local id=$1
  { printf "STORAGE_BACKEND=rocksdb\nSTORAGE_PATH=/var/lib/goya/data\n"
    "${SSH[@]}" "$VPS_HOST" "sudo grep -E '^($SHARED_SECRETS)=' $VPS_ENV"
    bft_env "$id"
  } | "${SSH[@]}" "$(host_of "$id")" "$(write_private /etc/goya/env)"
}

write_vps_env() {
  { "${SSH[@]}" "$VPS_HOST" "sudo grep -vE '^(P2P_EXTERNAL_ADDRESS|BFT_[A-Z_]+|TRUSTED_BLOCK_SIGNERS|BOOTSTRAP_NODES)=' $VPS_ENV"
    bft_env v0
  } | "${SSH[@]}" "$VPS_HOST" "$(write_private $VPS_ENV)"
}

cutover() {
  local stamp id snapshot
  stamp=$(date -u +%Y%m%d%H%M%S)
  snapshot="$ROOT/ledger-$stamp.tar.gz"
  record_vps_key
  scp -q "target/x86_64-unknown-linux-gnu/release/rust-bc" "$VPS_HOST:goya-node-bft"
  "${SSH[@]}" "$VPS_HOST" "set -e
    sudo cp -a $VPS_ENV /home/admin/goya-node-env.before-bft-$stamp
    sudo systemctl stop goya-node
    sudo cp -a /opt/goya-node/cerulean-node-linux-amd64 /home/admin/cerulean-node.before-bft-$stamp
    sudo install -m 755 goya-node-bft /opt/goya-node/cerulean-node-linux-amd64 && rm -f goya-node-bft
    sudo tar czf /home/admin/goya-node-data.before-bft-$stamp.tar.gz -C /var/lib goya-node
    sudo chmod 600 /home/admin/goya-node-env.before-bft-$stamp /home/admin/goya-node-data.before-bft-$stamp.tar.gz"
  "${SSH[@]}" "$VPS_HOST" "sudo tar czf - -C $VPS_DATA --exclude=data/signing_key_mldsa65.bin --exclude=data/credential_issuer_key_p256.bin data blockchain_checkpoints" > "$snapshot"
  for id in $(node_ids); do
    "${SSH[@]}" "$(host_of "$id")" 'set -e
      sudo systemctl stop goya
      sudo find /var/lib/goya -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {} +
      sudo find /var/lib/goya/data -mindepth 1 -maxdepth 1 ! -name signing_key_mldsa65.bin -exec rm -rf {} +
      sudo tar xzf - -C /var/lib/goya
      sudo chown -R goya:goya /var/lib/goya' < "$snapshot"
    write_validator_env "$id"
  done
  write_vps_env
  rm -f "$snapshot"
  "${SSH[@]}" "$VPS_HOST" 'sudo systemctl start goya-node'
  for id in $(node_ids); do "${SSH[@]}" "$(host_of "$id")" 'sudo systemctl enable --now goya'; done
}

rollback() {
  local stamp=${1:?pass the before-bft timestamp}
  "${SSH[@]}" "$VPS_HOST" "set -e
    sudo systemctl stop goya-node
    sudo install -m 640 -o root -g goya /home/admin/goya-node-env.before-bft-$stamp $VPS_ENV
    sudo install -m 755 /home/admin/cerulean-node.before-bft-$stamp /opt/goya-node/cerulean-node-linux-amd64
    sudo rm -rf $VPS_DATA && sudo tar xzf /home/admin/goya-node-data.before-bft-$stamp.tar.gz -C /var/lib
    sudo systemctl start goya-node"
  for id in $(node_ids); do "${SSH[@]}" "$(host_of "$id")" 'sudo systemctl disable --now goya' || true; done
}

heights() {
  local id
  printf 'v0 %s\n' "$("${SSH[@]}" "$VPS_HOST" 'curl -fsSk -m 5 https://127.0.0.1:8080/api/v1/chain/info || curl -fsS -m 5 http://127.0.0.1:8080/api/v1/chain/info')"
  for id in $(node_ids); do
    printf '%s %s\n' "$id" "$("${SSH[@]}" "$(host_of "$id")" 'curl -fsSk -m 5 https://127.0.0.1:8080/api/v1/chain/info || curl -fsS -m 5 http://127.0.0.1:8080/api/v1/chain/info' || echo unreachable)"
  done
}

OPS_REGION=us-east-1
ROLE=goya-mainnet-node
VPS_USER=goya-mainnet-vps
TOPIC=goya-mainnet-alerts

backup_bucket() { echo "goya-mainnet-backups-$(aws --profile "$PROFILE" sts get-caller-identity --query Account --output text)"; }

ops_policy() {
  cat <<EOF
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"cloudwatch:PutMetricData","Resource":"*","Condition":{"StringEquals":{"cloudwatch:namespace":"Goya"}}},
 {"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::$(backup_bucket)/*"}]}
EOF
}

ensure_backup_bucket() {
  local bucket
  bucket=$(backup_bucket)
  aws_in "$OPS_REGION" s3api head-bucket --bucket "$bucket" 2>/dev/null || aws_in "$OPS_REGION" s3api create-bucket --bucket "$bucket" >/dev/null
  aws_in "$OPS_REGION" s3api put-public-access-block --bucket "$bucket" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws_in "$OPS_REGION" s3api put-bucket-versioning --bucket "$bucket" --versioning-configuration Status=Enabled
  aws_in "$OPS_REGION" s3api put-bucket-lifecycle-configuration --bucket "$bucket" --lifecycle-configuration \
    '{"Rules":[{"ID":"expire-ledger","Status":"Enabled","Filter":{"Prefix":"ledger/"},"Expiration":{"Days":30},"NoncurrentVersionExpiration":{"NoncurrentDays":30}}]}'
}

ensure_node_role() {
  local id region
  aws_in "$OPS_REGION" iam get-role --role-name "$ROLE" >/dev/null 2>&1 || {
    aws_in "$OPS_REGION" iam create-role --role-name "$ROLE" --assume-role-policy-document \
      '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
    aws_in "$OPS_REGION" iam create-instance-profile --instance-profile-name "$ROLE" >/dev/null
    aws_in "$OPS_REGION" iam add-role-to-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE"
    sleep 10
  }
  aws_in "$OPS_REGION" iam put-role-policy --role-name "$ROLE" --policy-name goya-ops --policy-document "$(ops_policy)"
  for id in $(node_ids); do
    region=$(cat "$ROOT/$id/region")
    aws_in "$region" ec2 describe-iam-instance-profile-associations \
      --filters "Name=instance-id,Values=$(cat "$ROOT/$id/instance")" --query 'IamInstanceProfileAssociations[0]' --output text | grep -q "$ROLE" ||
      aws_in "$region" ec2 associate-iam-instance-profile --instance-id "$(cat "$ROOT/$id/instance")" \
        --iam-instance-profile "Name=$ROLE" >/dev/null
  done
}

ensure_vps_credentials() {
  aws_in "$OPS_REGION" iam get-user --user-name "$VPS_USER" >/dev/null 2>&1 || aws_in "$OPS_REGION" iam create-user --user-name "$VPS_USER" >/dev/null
  aws_in "$OPS_REGION" iam put-user-policy --user-name "$VPS_USER" --policy-name goya-ops --policy-document "$(ops_policy)"
  "${SSH[@]}" "$VPS_HOST" 'sudo test -s /root/.aws/credentials' && return 0
  aws_in "$OPS_REGION" iam create-access-key --user-name "$VPS_USER" \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text |
    awk '{print "[default]\naws_access_key_id = " $1 "\naws_secret_access_key = " $2}' |
    "${SSH[@]}" "$VPS_HOST" "sudo install -d -m 700 /root/.aws && sudo sh -c 'umask 077; cat > /root/.aws/credentials'"
}

ensure_alerts() {
  local email="${ALERT_EMAIL:?set ALERT_EMAIL to the address that receives node alerts}" topic id
  topic=$(aws_in "$OPS_REGION" sns create-topic --name "$TOPIC" --query TopicArn --output text)
  aws_in "$OPS_REGION" sns list-subscriptions-by-topic --topic-arn "$topic" --query 'Subscriptions[].Endpoint' --output text | grep -qw "$email" ||
    aws_in "$OPS_REGION" sns subscribe --topic-arn "$topic" --protocol email --notification-endpoint "$email" >/dev/null
  for id in v0 $(node_ids); do
    aws_in "$OPS_REGION" cloudwatch put-metric-alarm --alarm-name "goya-$id-down" \
      --alarm-description "Goya validator $id stopped reporting a healthy API for 5 minutes" \
      --namespace Goya --metric-name Healthy --dimensions "Name=Node,Value=$id" \
      --statistic SampleCount --period 60 --evaluation-periods 5 --threshold 1 \
      --comparison-operator LessThanThreshold --treat-missing-data breaching \
      --alarm-actions "$topic" --ok-actions "$topic"
  done
}

install_ops() {
  local id=$1 host=$2 data_dir=$3 service=$4 recipient bucket
  recipient=$(age-keygen -y "${BACKUP_AGE_KEY:-$HOME/.goya-backup/age.key}")
  bucket=$(backup_bucket)
  "${SSH[@]}" "$host" "set -e
    command -v age >/dev/null || { sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq age >/dev/null; }
    command -v aws >/dev/null || sudo snap install aws-cli --classic >/dev/null
    sudo tee /usr/local/bin/goya-heartbeat >/dev/null <<'SCRIPT'
#!/bin/sh
{ curl -fsSk -m 5 https://127.0.0.1:$API_PORT/api/v1/health || curl -fsS -m 5 http://127.0.0.1:$API_PORT/api/v1/health; } >/dev/null &&
  aws cloudwatch put-metric-data --region $OPS_REGION --namespace Goya --metric-name Healthy --dimensions Node=$id --value 1
SCRIPT
    sudo tee /usr/local/bin/goya-backup >/dev/null <<'SCRIPT'
#!/bin/sh
set -e
archive=/var/tmp/goya-ledger-$id.tar.gz
trap 'rm -f \$archive \$archive.age; systemctl start $service' EXIT
systemctl stop $service
tar czf \$archive -C $data_dir --exclude=data/signing_key_mldsa65.bin data blockchain_checkpoints
systemctl start $service
age -r $recipient -o \$archive.age \$archive
aws s3 cp --region $OPS_REGION --only-show-errors \$archive.age s3://$bucket/ledger/$id-\$(date -u +%Y%m%dT%H%M%SZ).tar.gz.age
SCRIPT
    sudo chmod 755 /usr/local/bin/goya-heartbeat /usr/local/bin/goya-backup
    printf 'PATH=/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\n* * * * * root /usr/local/bin/goya-heartbeat\n' | sudo tee /etc/cron.d/goya-heartbeat >/dev/null
    sudo cat $data_dir/data/signing_key_mldsa65.bin | age -r $recipient |
      sudo aws s3 cp --region $OPS_REGION --only-show-errors - s3://$bucket/keys/$id-signing_key_mldsa65.bin.age"
}

ops() {
  local id
  ensure_backup_bucket
  ensure_node_role
  ensure_vps_credentials
  ensure_alerts
  install_ops v0 "$VPS_HOST" "$VPS_DATA" goya-node
  for id in $(node_ids); do install_ops "$id" "$(host_of "$id")" /var/lib/goya goya; done
  "${SSH[@]}" "$(host_of v1)" "printf 'PATH=/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\n20 3 * * * root /usr/local/bin/goya-backup\n' | sudo tee /etc/cron.d/goya-backup >/dev/null"
}

provision() {
  local region id
  for region in $(regions); do prepare_region "$region"; done
  for id in $(node_ids); do launch_validator "$id"; done
  open_validator_firewall
  for id in $(node_ids); do install_validator "$id"; done
}

"$@"
