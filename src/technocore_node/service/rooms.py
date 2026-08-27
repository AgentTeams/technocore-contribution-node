"""Room names derived from the node's own DID.

Deriving them from a fingerprint rather than picking a word does two things: it makes a
collision with somebody else's room very unlikely without coordination, and it ties the
names to the identity, so a reader who has the DID can compute where to look.
"""

from __future__ import annotations

from ..crypto import didkey

MAILBOX_PREFIX = "mb-tc-jobs-"
RESULT_ROOM_PREFIX = "d-tc-contrib-"
ANNOUNCE_ROOM = "lobby"


def short_fingerprint(did: str) -> str:
    """The first 8 hex characters of the DID's fingerprint."""
    return didkey.fingerprint(did)[:8]


def mailbox_room(did: str, *, suffix: str = "") -> str:
    """This node's public job mailbox. Signed writes only, enforced by the server."""
    return f"{MAILBOX_PREFIX}{short_fingerprint(did)}{suffix}"


def result_room(did: str, *, suffix: str = "") -> str:
    """This node's owned result room.

    Every non-test receipt is published here as well as to the requester's reply room,
    along with the profile attestation and release notices. Only this node's key can write
    to it, which is what makes it an auditable record rather than a claim: a reply room
    belongs to the requester, who can post whatever they like into it.
    """
    return f"{RESULT_ROOM_PREFIX}{short_fingerprint(did)}{suffix}"
