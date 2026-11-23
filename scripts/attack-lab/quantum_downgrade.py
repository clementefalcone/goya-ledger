import base64
import hashlib
import json
import os
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attack_suite as lab

RELYING_PARTY = "verifier.attack-lab"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_json(value):
    return b64url(json.dumps(value, separators=(",", ":")).encode())


def es256(private_key, signing_input):
    r, s = decode_dss_signature(private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def p256_jwk(private_key):
    numbers = private_key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big"))}


def compact_jwt(header, payload, sign):
    signing_input = f"{b64url_json(header)}.{b64url_json(payload)}"
    return f"{signing_input}.{b64url(sign(signing_input))}"


def registered(identity, recovery_commitment=None):
    lab.register(0, identity, recovery_commitment=recovery_commitment)
    return lab.wait_until(lambda: lab.call(0, "GET", f"/store/identities/{identity.did}")[0] == 200, 30)


class Issuer:
    def __init__(self):
        self.did_key = lab.Identity()
        if not any(registered(self.did_key) for _ in range(3)):
            raise RuntimeError(f"issuer {self.did_key.did[:24]}... was never registered; results would be inconclusive")
        self.credential_key = ec.generate_private_key(ec.SECP256R1())
        jwk = p256_jwk(self.credential_key)
        message = f"oid4vci:issuer-key:{self.did_key.did}:{jwk['x']}:{jwk['y']}:1"
        self.registration = lab.call(0, "POST", f"/issuers/{self.did_key.did}/credential-key", {
            "jwk": jwk, "registered_at": 1, "public_key": self.did_key.public_key.hex(),
            "signature": self.did_key.sign(message),
        })[0]
        self.iss = f"https://node.attack-lab/api/v1/issuers/{self.did_key.did}"

    def credential(self, given_name, holder_jwk, header=None, sign=None):
        disclosure = b64url_json([b64url(os.urandom(16)), "given_name", given_name])
        now = int(time.time())
        payload = {"iss": self.iss, "sub": "holder", "iat": now, "exp": now + 3600,
                   "vct": "urn:attack-lab:pid", "_sd": [b64url(hashlib.sha256(disclosure.encode()).digest())],
                   "_sd_alg": "sha-256", "cnf": {"jwk": holder_jwk}}
        issuer_jwt = compact_jwt(header or {"alg": "ES256", "typ": "vc+sd-jwt"}, payload,
                                 sign or (lambda signing_input: es256(self.credential_key, signing_input)))
        return f"{issuer_jwt}~{disclosure}~"

    def anchor(self, sd_jwt):
        issuer_jwt = sd_jwt.split("~")[0]
        commitment = hashlib.sha256(issuer_jwt.encode()).hexdigest()
        anchor_id = f"sd-jwt:{commitment}"
        now = int(time.time())
        credential = {"id": anchor_id, "issuer_did": self.did_key.did, "subject_did": anchor_id,
                      "cred_type": "urn:attack-lab:pid", "issued_at": now, "expires_at": now + 3600,
                      "revoked_at": None, "claims": None, "status": "active",
                      "claims_commitment": commitment, "claims_salt": None}
        message = (f"credential:issue:{anchor_id}:{self.did_key.did}:{anchor_id}:urn:attack-lab:pid:"
                   f"{now}:{now + 3600}:{commitment}")
        status = lab.call(0, "POST", "/store/credentials", {
            **credential, "signature": self.did_key.sign(message),
            "issuer_public_key": self.did_key.public_key.hex(),
        })[0]
        lab.wait_until(lambda: lab.call(0, "GET", f"/store/credentials/{anchor_id}")[0] == 200, 30)
        return status


def key_binding(holder_key, sd_jwt, nonce):
    payload = {"aud": RELYING_PARTY, "nonce": nonce, "iat": int(time.time()),
               "sd_hash": b64url(hashlib.sha256(sd_jwt.encode()).digest())}
    return compact_jwt({"alg": "ES256", "typ": "kb+jwt"}, payload,
                       lambda signing_input: es256(holder_key, signing_input))


def present(build_vp_token):
    status, body = lab.call(0, "POST", "/oid4vp/request", {
        "client_id": RELYING_PARTY, "response_uri": "https://verifier.attack-lab/cb",
        "dcql_query": {"credentials": [{"id": "pid", "format": "vc+sd-jwt",
                                        "claims": [{"path": ["$.given_name"]}]}]},
    })
    request = body["data"]
    status, body = lab.call(0, "POST", "/oid4vp/response",
                            {"vp_token": build_vp_token(request["nonce"]), "state": request["state"]})
    code = body.get("error", {}).get("code") if isinstance(body, dict) and body.get("error") else ""
    return f"{status} {code}".strip(), status


def accepted(status):
    return isinstance(status, int) and 200 <= status < 300


def verifier_attacks(issuer):
    holder_key = ec.generate_private_key(ec.SECP256R1())
    legitimate = issuer.credential("Ada", p256_jwk(holder_key))
    anchor_status = issuer.anchor(legitimate)

    def honest(nonce):
        return legitimate + key_binding(holder_key, legitimate, nonce)

    thief_key = ec.generate_private_key(ec.SECP256R1())

    def stolen(nonce):
        return legitimate + key_binding(thief_key, legitimate, nonce)

    def shor_forgery(nonce):
        forged = issuer.credential("Mallory", p256_jwk(thief_key))
        return forged + key_binding(thief_key, forged, nonce)

    attacker_ed25519 = Ed25519PrivateKey.generate()

    def eddsa_confusion(nonce):
        forged = issuer.credential("Mallory", p256_jwk(thief_key), {"alg": "EdDSA", "typ": "vc+sd-jwt"},
                                   lambda signing_input: attacker_ed25519.sign(signing_input.encode()))
        return forged + key_binding(thief_key, forged, nonce)

    def none_algorithm(nonce):
        forged = issuer.credential("Mallory", p256_jwk(thief_key), {"alg": "none", "typ": "vc+sd-jwt"},
                                   lambda signing_input: b"")
        return forged + key_binding(thief_key, forged, nonce)

    def hmac_with_public_key(nonce):
        import hmac
        public_jwk = json.dumps(p256_jwk(issuer.credential_key)).encode()
        forged = issuer.credential("Mallory", p256_jwk(thief_key), {"alg": "HS256", "typ": "vc+sd-jwt"},
                                   lambda signing_input: hmac.new(public_jwk, signing_input.encode(),
                                                                  hashlib.sha256).digest())
        return forged + key_binding(thief_key, forged, nonce)

    control, control_status = present(honest)
    rows = [("CONTROL: holder presents an anchored credential", control, accepted(control_status))]
    for name, build in [
        ("Shor-forged ES256 credential (SIMULATED: attacker holds the P-256 key)", shor_forgery),
        ("alg confusion: EdDSA signature by an attacker key", eddsa_confusion),
        ("alg confusion: alg=none", none_algorithm),
        ("alg confusion: HS256 keyed with the issuer's public JWK", hmac_with_public_key),
        ("stolen credential presented with the thief's key binding", stolen),
    ]:
        observed, status = present(build)
        rows.append((name, observed, not accepted(status)))
    return anchor_status, rows


def identity_downgrades():
    classical = Ed25519PrivateKey.generate()
    classical_public = lab.raw_public(classical)
    classical_did = lab.did_of(classical_public)
    content_hash = os.urandom(32).hex()
    labelled_ml_dsa = lab.call(0, "POST", "/notarize", {
        "content_hash": content_hash, "signer": classical_did, "public_key": classical_public.hex(),
        "signature": classical.sign(f"notarize:{classical_did}:{content_hash}".encode()).hex(),
        "signature_algorithm": "MlDsa65",
    })[0]
    now = int(time.time())
    registered_as_ml_dsa = lab.call(0, "POST", "/store/identities", {
        "did": classical_did, "public_key": classical_public.hex(), "created_at": now, "updated_at": now,
        "status": "active", "signature_algorithm": "MlDsa65",
        "signature": classical.sign(f"identity:register:{classical_did}".encode()).hex(),
    })[0]

    owner, recovery, next_recovery = lab.Identity(), lab.Identity(), lab.Identity()
    if not any(registered(owner, recovery.did) for _ in range(3)):
        raise RuntimeError(f"owner {owner.did[:24]}... was never registered; results would be inconclusive")
    message = f"identity:rotate:{owner.did}:{classical_public.hex()}:{next_recovery.did}"
    rotated_to_classical = lab.call(0, "POST", f"/identity/{owner.did}/rotate", {
        "new_public_key": classical_public.hex(), "recovery_public_key": recovery.public_key.hex(),
        "new_recovery_commitment": next_recovery.did, "recovery_signature": recovery.sign(message),
        "new_key_signature": classical.sign(message.encode()).hex(),
    })[0]

    sha3 = lambda text: hashlib.sha3_256(text.encode()).hexdigest()
    entry = {"entry_id": "b0b0cafe", "kind": "reader", "label": "reader",
             "sealed_key": classical_public.hex()}
    vault_message = (f"identity:vault:add:{owner.did}:{entry['entry_id']}:reader:"
                     f"{sha3(entry['label'])}:{sha3(entry['sealed_key'])}")
    classical_reader = lab.call(0, "POST", f"/identity/{owner.did}/vault",
                                {**entry, "signature": owner.sign(vault_message)})[0]
    return [
        ("Ed25519 signature labelled ML-DSA-65 (notarize)", labelled_ml_dsa),
        ("Ed25519 key registered as an ML-DSA-65 identity", registered_as_ml_dsa),
        ("Rotate an ML-DSA identity to a classical key", rotated_to_classical),
        ("Classical reader key in the vault", classical_reader),
    ]


def main():
    issuer = Issuer()
    lab.call(0, "POST", "/oid4vp/rp", {"client_id": RELYING_PARTY, "name": "Attack lab verifier",
                                       "redirect_uris": ["https://verifier.attack-lab/cb"]})
    anchor_status, verifier_rows = verifier_attacks(issuer)
    print(f"issuer credential key: {issuer.registration}; legitimate anchor: {anchor_status}\n")
    rows = verifier_rows + [(name, str(status), not accepted(status)) for name, status in identity_downgrades()]
    for name, observed, held in rows:
        print(f"  {'HELD    ' if held else 'BREACHED'} {observed:<28} {name}")
    report_path = sys.argv[1] if len(sys.argv) > 1 else "quantum_downgrade.json"
    with open(report_path, "w") as report:
        json.dump([{"attack": name, "observed": observed, "held": held} for name, observed, held in rows],
                  report, indent=2)
    print(f"\n{sum(held for _, _, held in rows)}/{len(rows)} held; report at {report_path}")


if __name__ == "__main__":
    main()
