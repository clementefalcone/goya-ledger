import base64
import json
import os
import sys
from collections import Counter

from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attack_suite as lab

QUANTUM_EXPOSURE = {
    "ML-DSA-65": "post-quantum (FIPS 204)",
    "MlDsa65": "post-quantum (FIPS 204)",
    "SLH-DSA-128s": "post-quantum (FIPS 205)",
    "SlhDsa128s": "post-quantum (FIPS 205)",
    "Ed25519": "broken by Shor",
    "EdDSA": "broken by Shor",
    "ES256": "broken by Shor",
    "ECDSA-P256": "broken by Shor",
    "EcdsaP256": "broken by Shor",
    "P-256": "broken by Shor",
    "RS256": "broken by Shor",
    "RSA": "broken by Shor",
}

KEY_LENGTH_ALGORITHM = {64: "Ed25519", 3904: "ML-DSA-65", 130: "P-256"}


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def populate():
    issuer = lab.Identity()
    lab.register(0, issuer)
    for _ in range(3):
        lab.register(0, lab.Identity())
        lab.call(0, "POST", "/notarize", lab.notarization(lab.Identity(), os.urandom(32).hex()))
    credential_key = ec.generate_private_key(ec.SECP256R1())
    numbers = credential_key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64url(numbers.x.to_bytes(32, "big")),
           "y": b64url(numbers.y.to_bytes(32, "big"))}
    registered_at = 1
    message = f"oid4vci:issuer-key:{issuer.did}:{jwk['x']}:{jwk['y']}:{registered_at}"
    status, body = lab.call(0, "POST", f"/issuers/{issuer.did}/credential-key", {
        "jwk": jwk, "registered_at": registered_at,
        "public_key": issuer.public_key.hex(), "signature": issuer.sign(message),
    })
    return issuer.did, status, body


def data(path):
    status, body = lab.call(0, "GET", path)
    return body.get("data") if status == 200 and isinstance(body, dict) and "data" in body else body if status == 200 else None


def inventory():
    findings = []

    def add(surface, algorithm, count, evidence):
        findings.append({"surface": surface, "algorithm": algorithm, "count": count,
                         "exposure": QUANTUM_EXPOSURE.get(algorithm, "unclassified"), "evidence": evidence})

    latest = data("/store/blocks/latest") or 0
    block_algorithms = Counter()
    for height in range(latest + 1):
        block = data(f"/store/blocks/{height}") or {}
        block_algorithms[block.get("signature_algorithm", "unknown")] += 1
    for algorithm, count in block_algorithms.items():
        add("block signatures", algorithm, count, f"GET /store/blocks/0..{latest}")

    identities = data("/store/identities") or []
    identity_algorithms = Counter(KEY_LENGTH_ALGORITHM.get(len(record.get("public_key", "")), "unknown")
                                  for record in identities)
    for algorithm, count in identity_algorithms.items():
        add("identity keys (DIDs)", algorithm, count, "GET /store/identities")

    for record in identities:
        key = data(f"/issuers/{record['did']}/credential-key")
        if isinstance(key, dict) and key.get("jwk"):
            add("issuer credential keys", key["jwk"].get("crv", "unknown"), 1,
                f"GET /issuers/{record['did'][:20]}…/credential-key")

    metadata = lab.call(0, "GET", "/.well-known/openid-credential-issuer")[1]
    if isinstance(metadata, dict):
        for name, config in metadata.get("credential_configurations_supported", {}).items():
            for algorithm in config.get("credential_signing_alg_values_supported", []):
                add("credential signatures (OID4VCI)", algorithm, 1, f"issuer metadata: {name}")
            for algorithm in config.get("proof_types_supported", {}).get("jwt", {}).get(
                    "proof_signing_alg_values_supported", []):
                add("holder proof of possession (OID4VCI)", algorithm, 1, f"issuer metadata: {name}")

    session = data("/identity/auth/session-key") or {}
    if session.get("alg"):
        add("node login session key", session["alg"], 1, "GET /identity/auth/session-key")

    for service in (data("/tsl") or {}).get("services", []):
        for algorithm in service.get("algorithms", []):
            add(f"trust list: {service.get('name', '?')}", algorithm, 1, "GET /tsl")
    return findings


def main():
    issuer_did, status, _ = populate()
    print(f"populated lab; issuer credential key registration: {status}\n")
    findings = inventory()
    width = max(len(finding["surface"]) for finding in findings)
    for finding in sorted(findings, key=lambda finding: (finding["exposure"], finding["surface"])):
        print(f"{finding['surface']:<{width}}  {finding['algorithm']:<11} x{finding['count']:<3} {finding['exposure']}")
    exposed = [finding for finding in findings if finding["exposure"] == "broken by Shor"]
    print(f"\n{len(exposed)} of {len(findings)} exposed surfaces are broken by Shor")
    report_path = sys.argv[1] if len(sys.argv) > 1 else "quantum_inventory.json"
    with open(report_path, "w") as report:
        json.dump(findings, report, indent=2)
    print(f"report at {report_path}")


if __name__ == "__main__":
    main()
