#!/usr/bin/env python3
"""Sign and submit a job over HTTP, then check what comes back.

    python3 examples/send_job.py --key my.key --url https://agent.doptar.com

`--key` is a file holding 32 raw Ed25519 private key bytes, or 64 hex
characters. `--new-key PATH` writes one and prints the `did:key` it encodes.

> **This lane is not open yet.** `TCN_HTTP_JOB_INTAKE_ENABLED` is false on the
> public node, so `POST /v1/jobs` answers 404 there today. The script is the
> contract, written so it is ready and reviewable before the switch is thrown,
> not a description of something you can run against the public node right now.
> `--dry-run` prints exactly what would be sent, and works regardless.

Depends only on `cryptography` and the standard library.

## What you are signing

    technocore-node/v1/http-job|<your did:key>|<nonce>|sha256:<hex>

where the hex is the SHA-256 of the RFC 8785 canonical form of your `job`
object. Two consequences worth understanding before you use this:

* The signature covers a **hash of the body**, so editing any field of the job
  after signing invalidates it. Sign the object you are actually sending.
* The tag at the front is why a signature made here cannot be replayed as a
  Technocore room message, and vice versa: a room payload is `<room>|<nonce>|
  <text>`, and no room can be named `technocore-node/v1/http-job` because a
  room name may not contain `/`.

`nonce` must be an integer strictly greater than the last one this node
accepted from your DID. `GET /v1/jobs/signing-payload?did=…` reports the floor.
It is a replay defence, not a sequence number: gaps are fine, going backwards
is not.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover - a dependency message, not logic
    sys.exit("this needs `cryptography`: pip install cryptography")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_receipt import canonical, did_to_public_key

HTTP_JOB_DOMAIN = "technocore-node/v1/http-job"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

#: A job small enough to read and deterministic enough to check by hand: the
#: canonical form of this value is `{"a":[1,2],"b":1}` and its SHA-256 is fixed.
EXAMPLE_JOB: dict[str, Any] = {
    "v": "1",
    "type": "job",
    "job_id": "example-0000000001",
    "task": "canonical_json_sha256",
    # Required by the schema because the room lane replies there. Over HTTP the
    # answer comes back in the response, so this is unused — but the two lanes
    # share one schema deliberately, rather than drifting into two.
    "reply_room": "mb-p-unused-over-http",
    "input": {"value": {"b": 1, "a": [1, 2]}},
}


def encode_did(key: Ed25519PrivateKey) -> str:
    """The `did:key:z6Mk…` for an Ed25519 private key."""
    body = b"\xed\x01" + key.public_key().public_bytes_raw()
    n = int.from_bytes(body, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return "did:key:z" + "1" * (len(body) - len(body.lstrip(b"\x00"))) + out


def sign_job(key: Ed25519PrivateKey, did: str, job: dict[str, Any], nonce: int) -> dict[str, Any]:
    """The envelope to POST. See the module docstring for what is covered."""
    digest = hashlib.sha256(canonical(job).encode("utf-8")).hexdigest()
    payload = f"{HTTP_JOB_DOMAIN}|{did}|{nonce}|sha256:{digest}"
    sig = base64.urlsafe_b64encode(key.sign(payload.encode("utf-8"))).decode().rstrip("=")
    return {"did": did, "sig": sig, "nonce": str(nonce), "job": job}


def load_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes().strip()
    if len(raw) == 64:
        raw = bytes.fromhex(raw.decode())
    if len(raw) != 32:
        raise ValueError(f"{path} is neither 32 raw bytes nor 64 hex characters")
    return Ed25519PrivateKey.from_private_bytes(raw)


def post(url: str, envelope: dict[str, Any]) -> tuple[int, Any]:
    request = urllib.request.Request(  # noqa: S310
        url,
        data=json.dumps(envelope).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, body


def next_nonce(origin: str, did: str) -> int:
    """One above the floor the node reports, or 1 if it will not say."""
    try:
        with urllib.request.urlopen(  # noqa: S310
            f"{origin}/v1/jobs/signing-payload?did={did}", timeout=30
        ) as response:
            return int(json.load(response)["next_nonce_must_exceed"]) + 1
    except (OSError, KeyError, ValueError):
        return 1


def main(argv: list[str]) -> int:
    def opt(name: str, default: str | None = None) -> str | None:
        return next((a.split("=", 1)[1] for a in argv if a.startswith(f"--{name}=")), default)

    if new := opt("new-key"):
        key = Ed25519PrivateKey.generate()
        path = Path(new)
        path.write_bytes(key.private_bytes_raw())
        path.chmod(0o600)
        print(f"wrote {path} (mode 600)")
        print(f"did:  {encode_did(key)}")
        return 0

    key_path = opt("key")
    if not key_path:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        key = load_key(Path(key_path))
    except (OSError, ValueError) as exc:
        print(f"could not load a key: {exc}", file=sys.stderr)
        return 2

    did = encode_did(key)
    # A self-check: if this file's DID encoder and the verifier's decoder ever
    # disagree, every signature below would be attributed to the wrong key.
    assert did_to_public_key(did).public_bytes_raw() == key.public_key().public_bytes_raw()

    origin = (opt("url") or "https://agent.doptar.com").rstrip("/")
    job = dict(EXAMPLE_JOB)
    if job_id := opt("job-id"):
        job["job_id"] = job_id
    nonce = int(opt("nonce") or 0) or next_nonce(origin, did)
    envelope = sign_job(key, did, job, nonce)

    print(f"from   {did}")
    print(f"to     {origin}/v1/jobs")
    print(f"nonce  {nonce}")
    print(f"job    {job['task']} / {job['job_id']}")
    print()

    if "--dry-run" in argv:
        print(json.dumps(envelope, indent=2))
        return 0

    status, body = post(f"{origin}/v1/jobs", envelope)
    print(f"HTTP {status}")
    print(json.dumps(body, indent=2) if isinstance(body, (dict, list)) else body)

    if status == 404:
        print("\nThis node has HTTP intake disabled. Nothing is wrong with your request.")
    elif status == 503:
        print("\nThe node is refusing work because it cannot presently prove what it did.")
    elif status == 200 and isinstance(body, dict) and body.get("receipt_url"):
        print("\nNow check it independently:")
        print(f"  python3 examples/verify_receipt.py {body['receipt_url']}")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
