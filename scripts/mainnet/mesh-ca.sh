#!/usr/bin/env bash
set -euo pipefail

OUT="${1:?usage: mesh-ca.sh <out_dir> [id:ip ...]}"
shift || true
NODES=("$@")
if [ "${#NODES[@]}" -eq 0 ]; then
  NODES=(v0:162.254.32.12 v1:54.21.44.185 v2:98.88.218.208 v3:63.181.88.134)
fi

mkdir -p "$OUT"
chmod 700 "$OUT"

if [ ! -s "$OUT/ca-key.pem" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca-key.pem"
  openssl req -x509 -new -nodes -key "$OUT/ca-key.pem" -sha256 -days 1825 \
    -subj "/CN=goya-validator-mesh-ca" -out "$OUT/ca-cert.pem"
  chmod 600 "$OUT/ca-key.pem"
  echo "CA created: $OUT/ca-cert.pem"
else
  echo "CA exists: $OUT/ca-cert.pem (reusing)"
fi

for pair in "${NODES[@]}"; do
  id=${pair%%:*}
  ip=${pair#*:}
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/$id-key.pem"
  openssl req -new -key "$OUT/$id-key.pem" -subj "/CN=$id" -out "$OUT/$id.csr"
  cat > "$OUT/$id-ext.cnf" <<EOF
subjectAltName = IP:$ip, DNS:$id
extendedKeyUsage = serverAuth, clientAuth
EOF
  openssl x509 -req -in "$OUT/$id.csr" \
    -CA "$OUT/ca-cert.pem" -CAkey "$OUT/ca-key.pem" -CAcreateserial \
    -days 825 -sha256 -extfile "$OUT/$id-ext.cnf" -out "$OUT/$id-cert.pem"
  rm -f "$OUT/$id.csr" "$OUT/$id-ext.cnf"
  chmod 600 "$OUT/$id-key.pem"
  echo "issued $id  (IP SAN $ip)"
done

echo "done. distribute ca-cert.pem + <id>-cert.pem + <id>-key.pem to each node."
