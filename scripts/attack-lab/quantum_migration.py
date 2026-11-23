import hashlib
import json
import os
import subprocess
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attack_suite as lab


class ClassicalIdentity:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.public_key = self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                             serialization.PublicFormat.Raw)
        self.did = lab.did_of(self.public_key)

    def sign(self, message):
        return self.key.sign(message.encode()).hex()


def restart_network(binary):
    env = dict(os.environ, GOYA_NODE_BIN=binary)
    subprocess.run([lab.NETWORK_SCRIPT, "stop"], check=True, env=env, capture_output=True)
    subprocess.run([lab.NETWORK_SCRIPT, "start"], check=True, env=env, capture_output=True)
    lab.wait_until(lambda: all(lab.healthy(node) for node in range(lab.NODE_COUNT)), 60)
    time.sleep(5)


def register_classical(identity):
    now = int(time.time())
    return lab.call(0, "POST", "/store/identities", {
        "did": identity.did, "public_key": identity.public_key.hex(), "created_at": now,
        "updated_at": now, "status": "active", "signature_algorithm": "Ed25519",
        "signature": identity.sign(f"identity:register:{identity.did}"),
    })[0]


def sha3_hex(text):
    return hashlib.sha3_256(text.encode()).hexdigest()


def attempt_login(victim, shor_key):
    status, body = lab.call(0, "POST", "/identity/auth/challenge", {"did": victim.did})
    if status != 200:
        return status
    nonce = body["data"]["challenge"]
    return lab.call(0, "POST", "/identity/auth/verify", {
        "did": victim.did, "challenge": nonce, "signature": shor_key.sign(nonce),
    })[0]


def attempt_add_device(victim, shor_key, attacker):
    entry = {"entry_id": "a77ac4e2", "kind": "device", "label": "attacker",
             "sealed_key": attacker.public_key.hex()}
    message = (f"identity:vault:add:{victim.did}:{entry['entry_id']}:device:"
               f"{sha3_hex(entry['label'])}:{sha3_hex(entry['sealed_key'])}")
    status, body = lab.call(0, "POST", f"/identity/{victim.did}/vault",
                            {**entry, "signature": shor_key.sign(message)})
    return status if status != 400 else f"400 {body.get('message', '') if isinstance(body, dict) else body}"


def attempt_takeover(victim, shor_key, attacker, attacker_recovery):
    commit = lab.call(0, "POST", f"/identity/{victim.did}/recovery", {
        "recovery_commitment": attacker_recovery.did,
        "signature": shor_key.sign(f"identity:recovery:commit:{victim.did}:{attacker_recovery.did}"),
    })[0]
    new_key = attacker.public_key.hex()
    next_recovery = lab.Identity()
    message = f"identity:rotate:{victim.did}:{new_key}:{next_recovery.did}"
    rotate = lab.call(0, "POST", f"/identity/{victim.did}/rotate", {
        "new_public_key": new_key,
        "recovery_public_key": attacker_recovery.public_key.hex(),
        "new_recovery_commitment": next_recovery.did,
        "recovery_signature": attacker_recovery.sign(message),
        "new_key_signature": attacker.sign(message),
    })[0]
    _, record = lab.call(0, "GET", f"/store/identities/{victim.did}")
    owned_by_attacker = isinstance(record, dict) and record.get("data", {}).get("public_key") == new_key
    return commit, rotate, owned_by_attacker


def attempt_revoke(victim, shor_key):
    return lab.call(0, "POST", f"/identity/{victim.did}/revoke",
                    {"signature": shor_key.sign(f"identity:revoke:{victim.did}")})[0]


def attempt_notarize(victim, shor_key):
    content_hash = os.urandom(32).hex()
    return lab.call(0, "POST", "/notarize", {
        "content_hash": content_hash, "signer": victim.did, "public_key": victim.public_key.hex(),
        "signature": shor_key.sign(f"notarize:{victim.did}:{content_hash}"),
        "signature_algorithm": "Ed25519",
    })[0]


def accepted(status):
    return isinstance(status, int) and 200 <= status < 300


def main():
    legacy_binary, current_binary = sys.argv[1], sys.argv[2]
    restart_network(legacy_binary)
    victims = {name: ClassicalIdentity() for name in ("login", "device", "takeover", "revoke", "notarize")}
    def create(victim):
        for _ in range(3):
            register_classical(victim)
            if lab.wait_until(lambda: lab.call(0, "GET", f"/store/identities/{victim.did}")[0] == 200, 30):
                return True
        return False

    exists = {name: create(victim) for name, victim in victims.items()}
    print(f"legacy binary created classical identities: {exists}")
    if not all(exists.values()):
        print("some victims were not created; results would be inconclusive")
        return 1

    restart_network(current_binary)
    shor = {name: victim for name, victim in victims.items()}
    attacker, attacker_recovery = lab.Identity(), lab.Identity()
    commit, rotate, owned = attempt_takeover(victims["takeover"], shor["takeover"], attacker, attacker_recovery)
    paths = [
        ("Log in as the victim", attempt_login(victims["login"], shor["login"])),
        ("Add an attacker device to the victim's vault",
         attempt_add_device(victims["device"], shor["device"], attacker)),
        ("Commit an attacker recovery key", commit),
        ("Rotate the DID to the attacker's ML-DSA key", rotate),
        ("Revoke the victim's identity", attempt_revoke(victims["revoke"], shor["revoke"])),
        ("Notarize in the victim's name", attempt_notarize(victims["notarize"], shor["notarize"])),
    ]
    print("\nQ-day against identities created before ML-DSA became mandatory "
          "(Shor SIMULATED: the attacker is handed the Ed25519 private key)\n")
    for name, status in paths:
        print(f"  {'OPEN  ' if accepted(status) else 'CLOSED'} {status}  {name}")
    print(f"\n  DID permanently owned by the attacker after rotation: {owned}")
    report_path = sys.argv[3] if len(sys.argv) > 3 else "quantum_migration.json"
    with open(report_path, "w") as report:
        json.dump({"paths": [{"attack": name, "status": status, "open": accepted(status)} for name, status in paths],
                   "takeover_complete": owned}, report, indent=2)
    print(f"report at {report_path}")


if __name__ == "__main__":
    main()
