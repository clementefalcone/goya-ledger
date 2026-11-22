import concurrent.futures
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

NETWORK_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network.sh")
NODE_COUNT = 4


def api(node):
    return f"http://127.0.0.1:{19600 + 2 * node}/api/v1"


def p2p_port(node):
    return 19601 + 2 * node


@dataclass
class Outcome:
    attack: str
    front: str
    expected: str
    observed: str
    resisted: bool


def call(node, method, path, body=None, timeout=25, raw_body=None):
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
    request = urllib.request.Request(f"{api(node)}{path}", data=data, method=method,
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        payload = error.read()
        try:
            return error.code, json.loads(payload)
        except ValueError:
            return error.code, payload[:200].decode(errors="replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError, socket.timeout) as error:
        return None, str(error)


def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def did_of(public_key):
    return "did:goya:" + hashlib.sha3_512(public_key).hexdigest()


class Identity:
    def __init__(self):
        self.key = MLDSA65PrivateKey.generate()
        self.public_key = raw_public(self.key)
        self.did = did_of(self.public_key)

    def sign(self, message):
        return self.key.sign(message.encode()).hex()


def notarization(signer, content_hash, claimed_did=None, public_key=None, signature=None, algorithm="MlDsa65"):
    did = claimed_did or signer.did
    return {
        "content_hash": content_hash,
        "signer": did,
        "public_key": (public_key or signer.public_key).hex(),
        "signature": signature or signer.sign(f"notarize:{did}:{content_hash}"),
        "signature_algorithm": algorithm,
    }


def register(node, identity, recovery_commitment=None, signer=None):
    message = f"identity:register:{identity.did}" + (f":{recovery_commitment}" if recovery_commitment else "")
    now = int(time.time())
    record = {
        "did": identity.did,
        "public_key": identity.public_key.hex(),
        "created_at": now,
        "updated_at": now,
        "status": "active",
        "signature_algorithm": "MlDsa65",
        "signature": (signer or identity).sign(message),
    }
    if recovery_commitment:
        record["recovery_commitment"] = recovery_commitment
    return call(node, "POST", "/store/identities", record)


def is_rejected(status):
    return status is not None and 400 <= status < 500


def healthy(node):
    status, _ = call(node, "GET", "/health", timeout=5)
    return status == 200


def height(node):
    status, body = call(node, "GET", "/health", timeout=5)
    return body["data"]["blockchain"]["height"] if status == 200 else None


def network(*args):
    subprocess.run([NETWORK_SCRIPT, *args], check=True, capture_output=True)


def wait_until(predicate, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(1)
    return False


def attack_forged_signature():
    signer = Identity()
    content_hash = os.urandom(32).hex()
    status, _ = call(0, "POST", "/notarize", notarization(signer, content_hash, signature=os.urandom(3309).hex()))
    return Outcome("Forged ML-DSA signature (random bytes)", "signatures", "4xx", str(status), is_rejected(status))


def attack_signer_spoofing():
    victim, attacker = Identity(), Identity()
    register(0, victim)
    content_hash = os.urandom(32).hex()
    body = notarization(attacker, content_hash, claimed_did=victim.did)
    status, _ = call(0, "POST", "/notarize", body)
    return Outcome("Notarize in a victim's name with the attacker's key", "signatures", "4xx", str(status),
                   is_rejected(status))


def attack_key_substitution():
    victim, attacker = Identity(), Identity()
    content_hash = os.urandom(32).hex()
    body = notarization(attacker, content_hash, claimed_did=victim.did, public_key=victim.public_key,
                        signature=attacker.sign(f"notarize:{victim.did}:{content_hash}"))
    status, _ = call(0, "POST", "/notarize", body)
    return Outcome("Victim's public key with the attacker's signature", "signatures", "4xx", str(status),
                   is_rejected(status))


def attack_classical_downgrade():
    key = Ed25519PrivateKey.generate()
    public_key = raw_public(key)
    did = did_of(public_key)
    content_hash = os.urandom(32).hex()
    body = {
        "content_hash": content_hash,
        "signer": did,
        "public_key": public_key.hex(),
        "signature": key.sign(f"notarize:{did}:{content_hash}".encode()).hex(),
        "signature_algorithm": "Ed25519",
    }
    status, _ = call(0, "POST", "/notarize", body)
    return Outcome("Downgrade to classical crypto (valid Ed25519)", "signatures", "4xx", str(status),
                   is_rejected(status))


def attack_did_takeover():
    victim, attacker = Identity(), Identity()
    status, _ = register(0, victim, recovery_commitment=attacker.did, signer=attacker)
    victim_status, _ = register(0, victim)
    observed = f"takeover {status}, real owner afterwards {victim_status}"
    return Outcome("Register a victim's key with the attacker as recovery", "identity", "takeover 4xx, owner 2xx",
                   observed, is_rejected(status) and victim_status in (200, 201))


def attack_unauthorized_revoke():
    victim, attacker = Identity(), Identity()
    register(0, victim)
    status, _ = call(0, "POST", f"/identity/{victim.did}/revoke",
                     {"signature": attacker.sign(f"identity:revoke:{victim.did}")})
    _, record = call(0, "GET", f"/store/identities/{victim.did}")
    still_active = isinstance(record, dict) and record.get("data", {}).get("status") == "active"
    return Outcome("Revoke someone else's identity", "identity", "4xx and identity still active",
                   f"{status}, active={still_active}", is_rejected(status) and still_active)


def attack_rotation_hijack():
    victim, attacker, attacker_recovery = Identity(), Identity(), Identity()
    register(0, victim)
    new_key = attacker.public_key.hex()
    message = f"identity:rotate:{victim.did}:{new_key}:{attacker_recovery.did}"
    status, _ = call(0, "POST", f"/identity/{victim.did}/rotate", {
        "new_public_key": new_key,
        "recovery_public_key": attacker_recovery.public_key.hex(),
        "new_recovery_commitment": attacker_recovery.did,
        "recovery_signature": attacker_recovery.sign(message),
        "new_key_signature": attacker.sign(message),
    })
    _, record = call(0, "GET", f"/store/identities/{victim.did}")
    key_kept = isinstance(record, dict) and record.get("data", {}).get("public_key") == victim.public_key.hex()
    return Outcome("Rotate someone else's key to the attacker's", "identity", "4xx and original key kept",
                   f"{status}, key_kept={key_kept}", is_rejected(status) and key_kept)


def attack_replay():
    signer = Identity()
    body = notarization(signer, os.urandom(32).hex())
    first, _ = call(0, "POST", "/notarize", body)
    second, _ = call(1, "POST", "/notarize", body)
    return Outcome("Replay an already accepted notarization on another node", "signatures",
                   "first 201, replay not 201", f"{first} then {second}", first == 201 and second != 201)


def attack_malformed_inputs():
    cases = {
        "invalid JSON": b"{not json",
        "10 MB body": json.dumps({"content_hash": "a" * 10_000_000}).encode(),
        "non-hex key": json.dumps(notarization(Identity(), os.urandom(32).hex(), public_key=b"zz" * 976)).encode(),
        "1 MB key": json.dumps({"content_hash": os.urandom(32).hex(), "signer": "did:goya:x",
                                "public_key": "ab" * 500_000, "signature": "00",
                                "signature_algorithm": "MlDsa65"}).encode(),
        "huge DID in path": None,
    }
    observed = {}
    for name, raw in cases.items():
        if raw is None:
            status, _ = call(0, "GET", "/store/identities/did:goya:" + "f" * 100_000)
        else:
            status, _ = call(0, "POST", "/notarize", raw_body=raw)
        observed[name] = status
    alive = healthy(0)
    resisted = alive and all(status is not None and 400 <= status < 500 for status in observed.values())
    return Outcome("Malformed and oversized inputs", "inputs", "all 4xx and node alive",
                   f"{observed}, alive={alive}", resisted)


def attack_flood():
    def hit(_):
        status, _ = call(0, "GET", "/store/identities", timeout=10)
        return status

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        statuses = list(pool.map(hit, range(2000)))
    counts = {str(code): statuses.count(code) for code in sorted(set(statuses), key=str)}
    alive = all(healthy(node) for node in range(NODE_COUNT))
    return Outcome("Flood of 2,000 concurrent requests at one node", "network", "node and network stay up",
                   f"{counts}, network alive={alive}", alive)


def attack_p2p_garbage():
    sent = 0
    for _ in range(200):
        try:
            with socket.create_connection(("127.0.0.1", p2p_port(0)), timeout=2) as connection:
                connection.sendall(os.urandom(4096))
                sent += 1
        except OSError:
            pass
    signer = Identity()
    status, _ = call(0, "POST", "/notarize", notarization(signer, os.urandom(32).hex()))
    return Outcome("200 garbage connections to the P2P port", "network", "node keeps deciding blocks (201)",
                   f"sent={sent}, notarization after={status}", status == 201)


def attack_crash_one_validator():
    network("stop_one", "3")
    signer = Identity()
    status, _ = call(0, "POST", "/notarize", notarization(signer, os.urandom(32).hex()))
    return Outcome("Take down 1 of 4 validators (f=1)", "consensus", "writes still commit (201)", str(status),
                   status == 201)


def attack_beyond_threshold():
    network("stop_one", "2")
    before = [height(node) for node in (0, 1)]
    signer = Identity()
    status, _ = call(0, "POST", "/notarize", notarization(signer, os.urandom(32).hex()), timeout=20)
    after = [height(node) for node in (0, 1)]
    no_progress = before == after
    return Outcome("Take down 2 of 4 validators (beyond f)", "consensus",
                   "no write commits: safety over liveness", f"status={status}, heights {before} -> {after}",
                   status != 201 and no_progress)


def attack_recovery_convergence():
    network("start_one", "2")
    network("start_one", "3")
    restarted = time.time()
    committed = wait_until(
        lambda: call(0, "POST", "/notarize", notarization(Identity(), os.urandom(32).hex()), timeout=15)[0] == 201,
        300,
    )
    recovery_seconds = time.time() - restarted
    converged = wait_until(lambda: len({height(node) for node in range(NODE_COUNT)}) == 1, 90)
    heights = [height(node) for node in range(NODE_COUNT)]
    digests = set()
    for node in range(NODE_COUNT):
        _, body = call(node, "GET", "/store/identities")
        records = sorted(body.get("data") or [], key=lambda record: record["did"]) if isinstance(body, dict) else []
        digests.add(hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()[:12])
    return Outcome("Nodes return, writes resume and state converges", "consensus",
                   "writes commit again; same height and same state on all 4",
                   f"first write after restart in {recovery_seconds:.0f}s, heights={heights}, "
                   f"identity state digests={sorted(digests)}",
                   committed and converged and len(digests) == 1)


def attack_harvest_now_forge_later():
    classical = Ed25519PrivateKey.generate()
    harvested_public_key = raw_public(classical)
    recovered_by_shor = classical
    message = b"transfer 1,000,000 CLP to the attacker"
    forged = recovered_by_shor.sign(message)
    try:
        classical.public_key().verify(forged, message)
        classical_accepts = True
    except InvalidSignature:
        classical_accepts = False
    did = did_of(harvested_public_key)
    content_hash = os.urandom(32).hex()
    status, _ = call(0, "POST", "/notarize", {
        "content_hash": content_hash,
        "signer": did,
        "public_key": harvested_public_key.hex(),
        "signature": recovered_by_shor.sign(f"notarize:{did}:{content_hash}".encode()).hex(),
        "signature_algorithm": "Ed25519",
    })
    return Outcome("Harvest now, forge later (SIMULATED Shor oracle)", "quantum",
                   "a classical system accepts the forgery; Goya rejects it",
                   f"classical verifier accepted={classical_accepts}, Goya={status}",
                   classical_accepts and is_rejected(status))


ATTACKS = [
    attack_forged_signature,
    attack_signer_spoofing,
    attack_key_substitution,
    attack_classical_downgrade,
    attack_replay,
    attack_did_takeover,
    attack_unauthorized_revoke,
    attack_rotation_hijack,
    attack_malformed_inputs,
    attack_p2p_garbage,
    attack_harvest_now_forge_later,
    attack_crash_one_validator,
    attack_beyond_threshold,
    attack_recovery_convergence,
    attack_flood,
]


def main():
    outcomes = []
    for attack in ATTACKS:
        started = time.time()
        try:
            outcome = attack()
        except Exception as error:
            outcome = Outcome(attack.__name__, "harness", "attack runs", f"harness error: {error!r}", False)
        outcomes.append(outcome)
        mark = "RESISTED" if outcome.resisted else "BREACHED"
        print(f"[{mark}] {outcome.attack} ({time.time() - started:.1f}s)\n          expected: {outcome.expected}\n"
              f"          observed: {outcome.observed}", flush=True)
    report_path = sys.argv[1] if len(sys.argv) > 1 else "attack_report.json"
    with open(report_path, "w") as report:
        json.dump([asdict(outcome) for outcome in outcomes], report, indent=2)
    resisted = sum(outcome.resisted for outcome in outcomes)
    print(f"\n{resisted}/{len(outcomes)} attacks resisted; report at {report_path}")
    return 0 if resisted == len(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
