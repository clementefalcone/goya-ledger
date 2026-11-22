#!/usr/bin/env bash
set -euo pipefail

ROOT="${ATTACK_NET_ROOT:-${TMPDIR:-/tmp}/goya-attack-lab}"
BIN="${GOYA_NODE_BIN:?set GOYA_NODE_BIN to the rust-bc binary}"
NODES=(0 1 2 3)

api_port() { echo $((19600 + 2 * $1)); }
p2p_port() { echo $((19601 + 2 * $1)); }

node_env() {
  echo STORAGE_BACKEND=rocksdb STORAGE_PATH="$ROOT/n$1/data" NETWORK_ID=goya-attack-lab \
    BIND_ADDR=127.0.0.1 RUST_BC_ENV=development SIGNING_ALGORITHM=ml-dsa-65 \
    CHECKPOINT_HMAC_SECRET="$(cat "$ROOT/checkpoint.secret")"
}

keygen() {
  mkdir -p "$ROOT"
  [ -s "$ROOT/checkpoint.secret" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ROOT/checkpoint.secret"
  for i in "${NODES[@]}"; do
    local dir="$ROOT/n$i"
    mkdir -p "$dir/data"
    if [ ! -s "$dir/data/signing_key_mldsa65.bin" ]; then
      (cd "$dir" && exec env $(node_env "$i") "$BIN" "$(api_port "$i")" "$(p2p_port "$i")" > keygen.log 2>&1) &
      local pid=$!
      for _ in $(seq 1 120); do
        [ -s "$dir/data/signing_key_mldsa65.bin" ] && break
        sleep 0.5
      done
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    python3 -c "import sys; print(open(sys.argv[1],'rb').read()[:1952].hex())" \
      "$dir/data/signing_key_mldsa65.bin" > "$dir/pk.hex"
  done
}

joined() { local IFS=,; echo "$*"; }

start_one() {
  local i=$1 dir="$ROOT/n$1" validators=() keys=() peers=() trusted=()
  [ -f "$dir/pid" ] && kill -0 "$(cat "$dir/pid")" 2>/dev/null && return 0
  for j in "${NODES[@]}"; do
    validators+=("v$j")
    keys+=("v$j:$(cat "$ROOT/n$j/pk.hex")")
    [ "$j" = "$i" ] && continue
    peers+=("127.0.0.1:$(p2p_port "$j")")
    trusted+=("$(cat "$ROOT/n$j/pk.hex")")
  done
  (cd "$dir" && exec env $(node_env "$i") BFT_NODE_ID="v$i" BFT_VALIDATORS="$(joined "${validators[@]}")" \
    BFT_VALIDATOR_KEYS="$(joined "${keys[@]}")" TRUSTED_BLOCK_SIGNERS="$(joined "${trusted[@]}")" \
    BOOTSTRAP_NODES="$(joined "${peers[@]}")" RUST_LOG=info \
    "$BIN" "$(api_port "$i")" "$(p2p_port "$i")" >> node.log 2>&1) &
  echo $! > "$dir/pid"
}

start() { for i in "${NODES[@]}"; do start_one "$i"; done; }

stop_one() {
  local pidfile="$ROOT/n$1/pid"
  [ -f "$pidfile" ] || return 0
  kill "$(cat "$pidfile")" 2>/dev/null || true
  rm -f "$pidfile"
}

stop() { for i in "${NODES[@]}"; do stop_one "$i"; done; }

wipe() { stop; rm -rf "$ROOT"; }

"$@"
