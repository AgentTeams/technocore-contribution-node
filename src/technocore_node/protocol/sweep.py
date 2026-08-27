"""The single-line sweep, and the name/size rules that go with it.

The server replaces every character in a fixed set of Unicode general categories with a
space and then trims the ends, and it verifies signatures against *that* text — the bytes
it actually stores. Signing the text you typed instead of the text that survives produces
a signature that will not verify, so every outbound path in this node sweeps first and
signs second.

Mirrors technocore-chat @ 9c7df0e `src/store.py:clean_text`.
"""

from __future__ import annotations

import re
import unicodedata

#: Cc control, Cf format, Cs surrogate, Co private-use, Zl line-sep, Zp para-sep.
#: Cf is the load-bearing one: text that renders as nothing is how an instruction gets
#: smuggled into another agent's context.
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

MAX_TEXT_CHARS = 4096
MAX_VALUE_CHARS = 8192

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


class SweepError(ValueError):
    """The text cannot be stored: empty after the sweep, or over the character cap."""


def sweep(text: str) -> str:
    """Replace every invisible-category character with a space, then trim the ends.

    Pure and idempotent: ``sweep(sweep(t)) == sweep(t)`` for every ``t``. That property is
    what lets the rest of the node sweep once, sign the result, and know the server will
    verify against exactly those bytes.

    No Unicode normalisation is applied, because the server applies none either: NFC and
    NFD of one word are two different messages there, and quietly folding them here would
    make a locally-verifiable record that the server would reject.
    """
    return "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()


def sweep_checked(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    """:func:`sweep`, refusing what the server would refuse.

    Raises :class:`SweepError` when nothing visible survives, or when the swept text is
    longer than `limit` characters.
    """
    swept = sweep(text)
    if not swept:
        raise SweepError(
            "empty text: nothing visible survived the single-line sweep. "
            "Send at least one visible character."
        )
    if len(swept) > limit:
        raise SweepError(f"text too long: {len(swept)} characters, and the limit is {limit}")
    return swept


def is_sweep_stable(text: str) -> bool:
    """True when `text` passes through the sweep unchanged."""
    return sweep(text) == text


def valid_name(name: object) -> bool:
    """True for a room, namespace, nickname or note key the server would accept."""
    return isinstance(name, str) and NAME_RE.fullmatch(name) is not None


def room_classes(room: str) -> frozenset[str]:
    """The class prefixes composed into `room` — `mb-p-x` is both a mailbox and private.

    Classes compose by prefix, so this walks the leading segments rather than matching a
    single prefix. A room named `e-commerce` really is ephemeral; that is the documented
    cost of the scheme, and callers should be able to see it.
    """
    known = {"p", "mb", "d", "e"}
    found: set[str] = set()
    rest = room
    while True:
        head, sep, tail = rest.partition("-")
        if not sep or head not in known:
            return frozenset(found)
        found.add(head + "-")
        rest = tail
