"""RFC 8785 canonicalisation — the basis of every hash this node publishes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from technocore_node.protocol.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    canonicalize,
    dumps_number,
    parse_strict,
)


def test_keys_are_sorted() -> None:
    assert canonicalize({"b": 1, "a": 2, "C": 3}) == '{"C":3,"a":2,"b":1}'


def test_no_insignificant_whitespace() -> None:
    assert canonicalize({"a": [1, 2, {"b": None}]}) == '{"a":[1,2,{"b":null}]}'


def test_keys_sort_by_utf16_code_unit_not_code_point() -> None:
    """An astral character encodes as a surrogate pair starting U+D800, so in UTF-16 it
    sorts *before* U+E000-U+FFFF — the opposite of Python's default code-point order."""
    astral, bmp = "\U0001f600", ""
    assert sorted([astral, bmp]) == [bmp, astral], "code-point order puts the BMP char first"
    out = canonicalize({astral: 1, bmp: 2})
    assert out.index(astral) < out.index(bmp), "UTF-16 order must put the astral key first"


def test_rfc8785_appendix_example() -> None:
    """The worked example from RFC 8785 (literal order in, canonical order out)."""
    value = json.loads(
        '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet '
        'With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face",'
        '"\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}'
    )
    expected = (
        '{"\\r":"Carriage Return","1":"One","":"Control",'
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
        '"\U0001f600":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert canonicalize(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0"),
        (-0.0, "0"),
        (1, "1"),
        (1.0, "1"),
        (-1.5, "-1.5"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e16, "10000000000000000"),
        (1e-7, "1e-7"),
        (1e-6, "0.000001"),
        (0.1, "0.1"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (9007199254740991, "9007199254740991"),
    ],
)
def test_numbers_match_ecmascript(value: float, expected: str) -> None:
    assert dumps_number(value) == expected


def test_number_vectors_generated_by_node_json_stringify() -> None:
    """3000+ doubles round-tripped through the reference implementation, V8's own.

    Regenerate with `node tests/fixtures/gen_es6_numbers.js`.
    """
    fixture = Path(__file__).parent.parent / "fixtures" / "es6_numbers.json"
    cases = json.loads(fixture.read_text())
    assert len(cases) > 3000
    for raw, expected in cases:
        assert dumps_number(raw) == expected


def test_nan_and_infinity_are_refused() -> None:
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalJSONError):
            dumps_number(bad)
        with pytest.raises(CanonicalJSONError):
            canonicalize({"x": bad})


def test_parse_strict_refuses_json_extensions() -> None:
    for bad in ["NaN", "Infinity", "-Infinity", "[NaN]"]:
        with pytest.raises(CanonicalJSONError):
            parse_strict(bad)


def test_string_escaping_is_minimal() -> None:
    assert canonicalize("a\nb") == '"a\\nb"'
    assert canonicalize("a\x01b") == '"a\\u0001b"'
    assert canonicalize('quote " and \\ backslash') == '"quote \\" and \\\\ backslash"'
    assert canonicalize("é日\U0001f642") == '"é日\U0001f642"'


def test_non_string_keys_are_refused() -> None:
    with pytest.raises(CanonicalJSONError):
        canonicalize({1: "x"})


def test_unsupported_types_are_refused() -> None:
    with pytest.raises(CanonicalJSONError):
        canonicalize({"x": {1, 2}})


def test_deep_nesting_is_bounded() -> None:
    deep: object = 1
    for _ in range(200):
        deep = [deep]
    with pytest.raises(CanonicalJSONError):
        canonicalize(deep)


def test_canonical_bytes_is_utf8() -> None:
    assert canonical_bytes({"é": 1}) == '{"é":1}'.encode()


def test_same_document_different_key_order_hashes_the_same() -> None:
    a = json.loads('{"x":1,"y":{"b":2,"a":3}}')
    b = json.loads('{"y":{"a":3,"b":2},"x":1}')
    assert canonical_bytes(a) == canonical_bytes(b)
