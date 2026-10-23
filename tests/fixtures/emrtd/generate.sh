#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -subj "/C=CL/O=Laboratorio/CN=TEST CSCA" \
  -keyout "$work/csca.key" -out "$work/csca.pem" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -subj "/C=CL/O=Laboratorio/CN=TEST CSCA" \
  -keyout "$work/rogue.key" -out "$work/rogue.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj "/C=CL/O=Laboratorio/CN=TEST DS" \
  -keyout "$work/ds.key" -out "$work/ds.csr" 2>/dev/null
openssl x509 -req -in "$work/ds.csr" -CA "$work/csca.pem" -CAkey "$work/csca.key" \
  -CAcreateserial -sha256 -days 3650 -out "$work/ds.pem" 2>/dev/null

mrz="IDCHL1000000005123456789<<<<<<8001014M3001017CHL<<<<<<<<<<<0PEREZ<SOTO<<JUAN<CARLOS<<<<<<"
python3 - "$mrz" > dg1.bin <<'PY'
import sys
mrz = sys.argv[1].encode()
inner = b"\x5f\x1f" + bytes([len(mrz)]) + mrz
sys.stdout.buffer.write(b"\x61" + bytes([len(inner)]) + inner)
PY
python3 - <<'PY'
data = bytearray(open("dg1.bin", "rb").read())
data[-1] ^= 0x01
open("dg1_tampered.bin", "wb").write(data)
PY

dg1_hash=$(openssl dgst -sha256 -binary dg1.bin | xxd -p -c 64)
cat > "$work/lds.cnf" <<EOF
asn1 = SEQUENCE:lds
[lds]
version = INTEGER:0
algorithm = SEQUENCE:sha256
hashes = SEQUENCE:hashes
[sha256]
oid = OID:2.16.840.1.101.3.4.2.1
[hashes]
dg1 = SEQUENCE:dg1
[dg1]
number = INTEGER:1
value = FORMAT:HEX,OCTETSTRING:$dg1_hash
EOF
openssl asn1parse -genconf "$work/lds.cnf" -out "$work/lds.der" -noout

sign_sod() {
  openssl cms -sign -binary -nodetach -nosmimecap -in "$work/lds.der" \
    -econtent_type 2.23.136.1.1.1 -md sha256 \
    -signer "$2" -inkey "$3" -outform DER -out "$work/sod.der"
  python3 - "$work/sod.der" "$1" <<'PY'
import sys
body = open(sys.argv[1], "rb").read()
n = len(body)
length = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
open(sys.argv[2], "wb").write(b"\x77" + length + body)
PY
}

sign_sod sod.bin "$work/ds.pem" "$work/ds.key"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -subj "/C=CL/O=Laboratorio/CN=TEST DS" \
  -keyout "$work/selfds.key" -out "$work/selfds.pem" 2>/dev/null
sign_sod sod_self_signed_ds.bin "$work/selfds.pem" "$work/selfds.key"

openssl x509 -in "$work/csca.pem" -outform DER -out csca.der
openssl x509 -in "$work/rogue.pem" -outform DER -out rogue_csca.der
