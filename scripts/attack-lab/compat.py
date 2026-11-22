import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey

NODE = sys.argv[1]
GOYA_SIGN = sys.argv[2]


def raw_public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def did_of(public_key):
    return "did:goya:" + hashlib.sha3_512(public_key).hexdigest()


def notarize(key, content_hash, signature_override=None):
    public_key = raw_public(key.public_key())
    did = did_of(public_key)
    signature = signature_override or key.sign(f"notarize:{did}:{content_hash}".encode())
    body = json.dumps({
        "content_hash": content_hash,
        "signer": did,
        "public_key": public_key.hex(),
        "signature": signature.hex(),
        "signature_algorithm": "MlDsa65",
    }).encode()
    request = urllib.request.Request(f"{NODE}/api/v1/notarize", data=body,
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


results = []


def check(name, passed):
    results.append(passed)
    print(("PASS " if passed else "FAIL ") + name)


key = MLDSA65PrivateKey.generate()
check("python-signed notarization accepted by node", notarize(key, os.urandom(32).hex()) == 201)

content_hash = os.urandom(32).hex()
tampered = bytearray(key.sign(b"something else"))
check("python signature over another message rejected", notarize(key, content_hash, bytes(tampered)) in (400, 401))

rust_key = json.loads(subprocess.check_output([GOYA_SIGN, "keygen", "ml-dsa-65"]))
message = "goya interop " + os.urandom(8).hex()
rust_signature = json.loads(subprocess.check_output(
    [GOYA_SIGN, "sign", "ml-dsa-65", rust_key["private_key"], message]))["signature"]
rust_public = MLDSA65PublicKey.from_public_bytes(bytes.fromhex(rust_key["public_key"]))
try:
    rust_public.verify(bytes.fromhex(rust_signature), message.encode())
    check("rust-signed message verified by python", True)
except InvalidSignature:
    check("rust-signed message verified by python", False)
check("goya-sign DID matches python derivation",
      rust_key["did"] == did_of(bytes.fromhex(rust_key["public_key"])))

sys.exit(0 if all(results) else 1)
