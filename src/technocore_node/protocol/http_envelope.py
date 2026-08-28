"""The signature envelope for jobs submitted over HTTP.

A second transport needs a second signature scheme, and the only interesting question is
what stops the two from being confused for each other.

**Domain separation.** A Technocore message signature covers ``<room>|<nonce>|<text>``.
If an HTTP submission were signed the same way, a signature captured from a public room —
where every signed message is world-readable — could be replayed into this endpoint, and
one lifted from here could be posted into a room. Both are the same failure: a signature
means "I authorised *this*", and it stops meaning that the moment two different requests
can share one. So every HTTP payload begins with a version-pinned constant that cannot
appear in a room payload, because a room name may not contain a colon.

**A nonce is not enough on its own.** It orders a requester's submissions and lets the
server reject an old one, but the requester chooses it. What makes a replay useless here
is the pair: a monotonic per-DID nonce *and* a body hash bound into the signed payload, so
altering the body invalidates the signature and reusing the signature cannot alter the
body.

The payload is:

    technocore-node/v1/http-job|<did>|<nonce>|<sha256 of the canonical body>

Every field before the hash is drawn from a character set that excludes ``|``: a DID is
``did:key:z6Mk`` plus base58btc, a nonce is digits, and the domain tag is a constant. The
delimiters therefore cannot be shifted by anything a caller supplies.
"""

from __future__ import annotations

import hashlib
import re

from ..crypto import didkey
from .canonical import canonical_bytes

#: Version-pinned, and part of the signed bytes. A v2 scheme gets a different tag, so a
#: signature made for one can never be accepted by the other — which is the point of
#: putting a version in a domain separator rather than only in a URL.
HTTP_JOB_DOMAIN = "technocore-node/v1/http-job"

SEPARATOR = "|"

#: The clock skew a submission may carry. Wide enough for an agent with a bad clock,
#: narrow enough that a captured request is not replayable indefinitely — and it is the
#: *second* line of defence: the stored nonce is the first.
MAX_SKEW_SECONDS = 300

NONCE_RE = re.compile(r"^[0-9]{1,19}$")


class HttpEnvelopeError(ValueError):
    """The submission is not a well-formed signed HTTP job."""


def body_digest(body: object) -> str:
    """`sha256:<hex>` over the RFC 8785 canonical form of the request body.

    Canonical, not raw bytes: two encodings of the same document must produce the same
    signature, or a proxy that reformats JSON would silently invalidate every request.
    """
    return "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


def http_job_payload(did: str, nonce: int | str, body: object) -> str:
    """The exact bytes an HTTP job signature covers."""
    return f"{HTTP_JOB_DOMAIN}{SEPARATOR}{did}{SEPARATOR}{nonce}{SEPARATOR}{body_digest(body)}"


def verify_http_job(did: str, signature: str, nonce: str, body: object) -> None:
    """Raise :class:`HttpEnvelopeError` unless this is a valid submission from `did`."""
    if not didkey.is_did(did):
        raise HttpEnvelopeError("did is not a valid Ed25519 did:key")
    if not NONCE_RE.fullmatch(nonce):
        raise HttpEnvelopeError("nonce must be 1-19 digits")
    if not didkey.SIG_RE.fullmatch(signature or ""):
        raise HttpEnvelopeError("sig must be 86 unpadded base64url characters")
    if not didkey.verify_ok(did, signature, http_job_payload(did, nonce, body)):
        raise HttpEnvelopeError(
            "signature does not cover this request. It must sign "
            f"'{HTTP_JOB_DOMAIN}|<did>|<nonce>|sha256:<hex of the RFC 8785 canonical body>' "
            "— a signature made for the Technocore room lane will not verify here, "
            "deliberately."
        )


def crosses_domains(technocore_room_payload: str) -> bool:
    """True if a room payload could ever be mistaken for an HTTP one.

    Kept as a function rather than a comment because it is the property the whole scheme
    rests on, and `tests/` asserts it rather than trusting the reasoning above.
    """
    return technocore_room_payload.startswith(HTTP_JOB_DOMAIN)
