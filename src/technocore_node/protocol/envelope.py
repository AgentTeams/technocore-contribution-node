"""Signature payloads, and the envelope a third party needs to re-verify a message.

Two payload shapes exist upstream and no others:

* a room message covers ``<room>|<nonce>|<text>``
* a note covers ``<namespace>|<key>|<nonce>|<value>``

In both cases the trailing component is the value *after* the single-line sweep. `seq`
and `ts` are assigned by the server after the signature is made and are therefore not
covered by it — a distinction this node states in every receipt it publishes, because a
reader who assumes otherwise would over-trust the ordering.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto import didkey
from .sweep import sweep

MESSAGE_SEPARATOR = "|"

# Why `|` is unambiguous here even though the trailing component may contain one: every
# component before it is constrained to a character set that excludes the separator. A
# room, namespace and note key must match ^[a-z0-9][a-z0-9_-]{0,47}$ and a nonce must
# match ^[0-9]{1,19}$, so a leading separator can only ever be a delimiter — a `|` inside
# the text or value cannot shift where the earlier fields end. The obligation that falls
# out of this: validate those components *before* signing, which every path here does.


def message_payload(room: str, nonce: int | str, text: str) -> str:
    """The exact bytes a room-message signature covers. `text` is swept here."""
    return f"{room}{MESSAGE_SEPARATOR}{nonce}{MESSAGE_SEPARATOR}{sweep(text)}"


def note_payload(namespace: str, key: str, nonce: int | str, value: str) -> str:
    """The exact bytes a signed-note signature covers. `value` is swept here."""
    return (
        f"{namespace}{MESSAGE_SEPARATOR}{key}{MESSAGE_SEPARATOR}"
        f"{nonce}{MESSAGE_SEPARATOR}{sweep(value)}"
    )


@dataclass(frozen=True, slots=True)
class SignedMessage:
    """Everything needed to re-verify one stored room message, offline.

    `seq` and `ts` are carried for provenance but are explicitly outside the signature.
    """

    room: str
    did: str
    nonce: int
    text: str
    sig: str
    seq: int | None = None
    ts: str | None = None

    @property
    def payload(self) -> str:
        return message_payload(self.room, self.nonce, self.text)

    def verify(self) -> None:
        """Raise :class:`DidError` / :class:`SignatureError` unless this envelope holds."""
        didkey.verify(self.did, self.sig, self.payload)

    def verify_ok(self) -> bool:
        return didkey.verify_ok(self.did, self.sig, self.payload)
