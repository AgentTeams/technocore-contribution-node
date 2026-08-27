"""RFC 8785 JSON Canonicalization Scheme (JCS).

Two hashes of "the same" JSON document must agree across implementations or a receipt
chain is worthless, so the canonicalisation is named and specified rather than invented:
**RFC 8785**, whose output is byte-identical to ECMAScript ``JSON.stringify`` over a
value with sorted keys.

Three parts carry all the risk, and each is implemented against the spec text rather than
approximated:

* **Key order** — by UTF-16 code unit, not code point. Python sorts strings by code point,
  which disagrees for astral characters (a surrogate pair starts at U+D800, so an astral
  key sorts *before* U+E000-U+FFFF in UTF-16 and *after* it by code point). Keys are
  therefore sorted on their UTF-16 big-endian encoding.
* **Numbers** — ECMAScript ``Number::toString``. Python's ``repr`` produces the same
  shortest round-tripping digits but chooses exponential form at different thresholds
  (``1e16`` is ``1e+16`` in Python and ``10000000000000000`` in JS), so the digits are
  extracted and re-formatted by the ES6 rules.
* **Strings** — the JSON escape set is exactly the eight short escapes plus ``\\u00xx`` for
  the remaining C0 controls. Everything else, non-ASCII included, is emitted literally.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

__all__ = ["CanonicalJSONError", "canonical_bytes", "canonicalize", "dumps_number"]

SCHEME = "RFC8785"

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalJSONError(ValueError):
    """The value cannot be canonicalised: NaN, Infinity, or an unsupported type."""


def dumps_number(value: float | int) -> str:
    """Serialise a JSON number exactly as ECMAScript ``Number::toString`` would."""
    if isinstance(value, bool):  # bool is an int subclass; never reachable via canonicalize
        raise CanonicalJSONError("bool is not a JSON number")
    if isinstance(value, int):
        # Up to 2**53 an integer is exact as a double, and ES6 prints it as plain digits
        # (it only reaches for an exponent past 1e21), so str() is already the answer.
        if abs(value) <= 2**53:
            return str(value)
        # Past that, RFC 8785 is explicit that a JSON number *is* an IEEE-754 double:
        # Python's parser happens to hand back an arbitrary-precision int for integer
        # syntax, but the canonical form is the one the double takes. The conversion is
        # lossy by the spec's own model, not by this implementation's choice.
        try:
            value = float(value)
        except OverflowError:
            raise CanonicalJSONError(
                f"integer with {len(str(abs(value)))} digits is outside the IEEE-754 "
                "double range RFC 8785 canonicalises over"
            ) from None
    if math.isnan(value) or math.isinf(value):
        raise CanonicalJSONError("NaN and Infinity are not JSON numbers")
    if value == 0:
        # -0.0 serialises as "0" in ECMAScript, sign and all.
        return "0"

    sign = "-" if value < 0 else ""
    # repr() gives the shortest digit string that round-trips, which is the same digit
    # string ES6 picks; only the choice of exponential form differs, and that is below.
    dec = Decimal(repr(abs(value)))
    digits = "".join(str(d) for d in dec.as_tuple().digits).rstrip("0") or "0"
    # value == 0.<digits> * 10**n, so n is where the decimal point falls in the digits.
    n = dec.adjusted() + 1
    k = len(digits)

    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    e = n - 1
    esign = "+" if e >= 0 else "-"
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{sign}{mantissa}e{esign}{abs(e)}"


def _dumps_string(value: str) -> str:
    out = ['"']
    for ch in value:
        escape = _ESCAPES.get(ch)
        if escape is not None:
            out.append(escape)
        elif ch < "\x20":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _sort_key(key: str) -> bytes:
    """Order object members by UTF-16 code unit, as RFC 8785 §3.2.3 requires."""
    return key.encode("utf-16-be", errors="surrogatepass")


def _serialize(value: Any, out: list[str], depth: int) -> None:
    if depth > 100:
        raise CanonicalJSONError("value nests deeper than 100 levels")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        # A lone surrogate parses happily out of JSON and then cannot be UTF-8 encoded.
        # Caught here rather than three frames later at `.encode()`, so a caller gets a
        # CanonicalJSONError the pipeline already knows how to refuse.
        if any("\ud800" <= c <= "\udfff" for c in value):
            raise CanonicalJSONError(
                "unpaired surrogate in a string: not valid UTF-8, so it has no "
                "canonical form and cannot be hashed"
            )
        out.append(_dumps_string(value))
    elif isinstance(value, int | float):
        out.append(dumps_number(value))
    elif isinstance(value, list | tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out, depth + 1)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        keys = list(value)
        if any(not isinstance(k, str) for k in keys):
            raise CanonicalJSONError("JSON object keys must be strings")
        for i, key in enumerate(sorted(keys, key=_sort_key)):
            if i:
                out.append(",")
            out.append(_dumps_string(key))
            out.append(":")
            _serialize(value[key], out, depth + 1)
        out.append("}")
    else:
        raise CanonicalJSONError(f"{type(value).__name__} is not a JSON type")


def canonicalize(value: Any) -> str:
    """The RFC 8785 canonical form of an already-parsed JSON value."""
    out: list[str] = []
    _serialize(value, out, 0)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    """:func:`canonicalize` as the UTF-8 bytes a digest is taken over."""
    return canonicalize(value).encode("utf-8")


def parse_strict(text: str) -> Any:
    """Parse JSON the way an evidentiary hash needs it parsed.

    Python's parser is more forgiving than JSON, and each thing it forgives becomes an
    ambiguity in a receipt:

    * ``NaN`` / ``Infinity`` / ``-Infinity`` are not JSON and have no canonical form.
    * **Duplicate keys** are the load-bearing one. Python keeps the last occurrence, so
      ``{"task":"a","task":"b"}`` hashes as if only ``"b"`` were ever written — while a
      verifier that rejects duplicates, or keeps the first, reads the same signed bytes
      differently. The signature would still verify and the two parties would disagree
      about what was signed, which is exactly the property a receipt exists to rule out.
      RFC 8785 canonicalises an already-parsed value and so cannot see this; it has to be
      refused at the parse.
    """

    def _reject_constant(value: str) -> float:
        raise CanonicalJSONError(f"{value} is not valid JSON")

    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                raise CanonicalJSONError(
                    f"duplicate object key {key!r}: the document has no single meaning, "
                    "so it cannot be canonicalised or hashed as evidence"
                )
            seen.add(key)
        return dict(pairs)

    return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_reject_duplicates)
