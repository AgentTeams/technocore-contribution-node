#!/usr/bin/env python3
"""Check a receipt from this node without trusting this node.

That is the entire point, so this file depends on nothing from
`technocore_node` — only `cryptography` for Ed25519 and the standard library.
Verification that runs the provider's own code proves the provider agrees with
itself. Reimplementing it here, from the spec, is what makes the receipt worth
anything to you.

    python3 examples/verify_receipt.py https://agent.doptar.com/v1/receipts/<job_id>
    python3 examples/verify_receipt.py receipt.json
    cat receipt.json | python3 examples/verify_receipt.py -

What is checked, and what each check does and does not tell you:

1. `receipt_hash` is the SHA-256 of the RFC 8785 canonical form of the receipt
   with `sig` and `receipt_hash` removed. Detects any edit to any other field.
2. `sig` is a valid Ed25519 signature by `provider_did` over the canonical form
   of the receipt with `sig` removed. Proves the holder of that key produced
   this exact receipt.
3. `provider_did` is the node's published DID — fetched from `/v1/info` when
   you pass a URL, or supplied with `--expect-did`. Without this, a valid
   signature by *some* key proves nothing about *whose*.

Not proof of anything else. `request_seq` is assigned by the server after the
signature is made and is provenance, not evidence. A receipt says the provider
claims to have done this work; whether the work was correct is what the task
output and `verify_receipt_chain` are for.

Exit status is 0 if every check passes, 1 if any fails, 2 on a usage error.
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - a dependency message, not logic
    sys.exit("this needs `cryptography`: pip install cryptography")

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"


# --------------------------------------------------------------- did:key


def did_to_public_key(did: str) -> Ed25519PublicKey:
    """`did:key:z6Mk…` to the Ed25519 key it encodes."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"not a did:key with a base58btc multibase tag: {did!r}")
    n = 0
    for char in did[len("did:key:z") :]:
        if char not in B58:
            raise ValueError(f"not base58btc: {char!r}")
        n = n * 58 + B58.index(char)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    # Each leading '1' is a zero byte that the integer conversion above drops.
    body = b"\x00" * (len(did) - len(did.lstrip("1")) - len("did:key:z")) + body
    if len(body) != 34 or not body.startswith(MULTICODEC_ED25519):
        raise ValueError("only ed25519-pub (z6Mk…) did:key identifiers are supported")
    return Ed25519PublicKey.from_public_bytes(body[2:])


def decode_signature(sig: str) -> bytes:
    """86 unpadded base64url characters to 64 raw bytes."""
    import base64

    if len(sig) != 86:
        raise ValueError(f"a signature is 86 base64url characters, got {len(sig)}")
    return base64.urlsafe_b64decode(sig + "==")


# ------------------------------------------------------- RFC 8785 (JCS)


def canonical(value: Any) -> str:
    """The RFC 8785 canonical form. Enough of it for a receipt.

    Receipts contain only strings, integers, booleans, objects and arrays — no
    floats — so the number rule reduces to Python's own integer rendering. A
    float here is refused rather than guessed at, because getting the shortest
    round-trip representation subtly wrong produces a hash that disagrees with
    the provider's for reasons nobody will enjoy finding.
    """
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("this reduced canonicaliser refuses floats; see protocol/canonical.py")
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 orders keys by UTF-16 code unit, which for the ASCII keys a
        # receipt uses is the same as ordering by code point.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{canonical(k)}:{canonical(v)}" for k, v in items) + "}"
    raise ValueError(f"not JSON: {type(value).__name__}")


def sha256_of(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def without(receipt: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in receipt.items() if k not in keys}


# ----------------------------------------------------------------- checks


def verify(receipt: dict[str, Any], expect_did: str | None) -> list[str]:
    """Every problem found, in order. An empty list means the receipt holds."""
    problems: list[str] = []

    for field in ("v", "type", "job_id", "provider_did", "receipt_hash", "sig"):
        if field not in receipt:
            problems.append(f"missing required field {field!r}")
    if problems:
        return problems
    if receipt["type"] != "receipt":
        problems.append(f"type is {receipt['type']!r}, not 'receipt'")

    recomputed = sha256_of(without(receipt, "sig", "receipt_hash"))
    if recomputed != receipt["receipt_hash"]:
        problems.append(
            f"receipt_hash does not match the content: "
            f"recomputed {recomputed}, receipt says {receipt['receipt_hash']}"
        )

    try:
        key = did_to_public_key(receipt["provider_did"])
        key.verify(decode_signature(receipt["sig"]), canonical(without(receipt, "sig")).encode())
    except InvalidSignature:
        problems.append("sig is not a valid signature by provider_did over this receipt")
    except ValueError as exc:
        problems.append(f"signature could not be checked: {exc}")

    if expect_did is None:
        problems.append(
            "provider_did was not checked against a known identity — a valid signature "
            "by an unknown key proves possession of that key and nothing more"
        )
    elif receipt["provider_did"] != expect_did:
        problems.append(f"signed by {receipt['provider_did']}, expected {expect_did}")

    return problems


# ------------------------------------------------------------------ main


def load(source: str) -> tuple[dict[str, Any], str | None]:
    """The receipt, and the DID to expect if the source can tell us."""
    if source == "-":
        return json.load(sys.stdin), None
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=30) as response:  # noqa: S310
            body = json.load(response)
        receipt = body.get("receipt", body)
        # Ask the node who it is, over the same TLS connection that served the
        # receipt. This is a convenience, not a root of trust: it is the node
        # vouching for itself. Pin the DID out of band and pass --expect-did
        # if the answer matters to you.
        origin = "/".join(source.split("/")[:3])
        try:
            with urllib.request.urlopen(f"{origin}/v1/info", timeout=30) as response:  # noqa: S310
                return receipt, json.load(response).get("did")
        except OSError:
            return receipt, None
    with open(source, encoding="utf-8") as handle:
        return json.load(handle), None


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--expect-did")]
    pinned = next(
        (a.split("=", 1)[1] for a in argv[1:] if a.startswith("--expect-did=")),
        None,
    )
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2

    try:
        receipt, discovered = load(args[0])
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read a receipt from {args[0]}: {exc}", file=sys.stderr)
        return 2

    expect = pinned or discovered
    problems = verify(receipt, expect)

    print(f"receipt   {receipt.get('receipt_id', '(no receipt_id)')}")
    print(f"job       {receipt.get('job_id', '(no job_id)')}")
    print(f"provider  {receipt.get('provider_did', '(none)')}")
    if pinned:
        print("           checked against the DID you pinned")
    elif discovered:
        print("           checked against the DID the node reports for itself")
    if receipt.get("internal_test"):
        print("note      internal_test: the node's own verification, not third-party use")
    print()

    if not problems:
        print("OK — content unmodified, signature valid, signed by the expected key.")
        return 0
    for problem in problems:
        print(f"FAIL — {problem}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
