"""The single-line sweep — the thing a signature is actually taken over."""

from __future__ import annotations

import unicodedata

import pytest

from technocore_node.protocol.sweep import (
    INVISIBLE_CATEGORIES,
    SweepError,
    is_sweep_stable,
    room_classes,
    sweep,
    sweep_checked,
    valid_name,
)


def test_control_characters_become_spaces() -> None:
    assert sweep("a\nb") == "a b"
    assert sweep("a\tb") == "a b"
    assert sweep("a\r\nb") == "a  b"


def test_ends_are_trimmed() -> None:
    assert sweep("  hi  ") == "hi"
    assert sweep("\n\nhi\n\n") == "hi"


def test_interior_runs_are_not_collapsed() -> None:
    """The server replaces and trims; it does not squeeze. Collapsing here would make a
    signature that the server refuses."""
    assert sweep("a\n\n\nb") == "a   b"


@pytest.mark.parametrize(
    "char",
    [
        "​",  # zero-width space (Cf)
        "‍",  # zero-width joiner (Cf)
        "‮",  # right-to-left override (Cf) — Trojan Source
        " ",  # line separator (Zl)
        " ",  # paragraph separator (Zp)
        "",  # private use (Co)
        "\U000e0041",  # Unicode tag character (Cf)
        "\x00",  # NUL (Cc)
        "\x85",  # C1 next-line (Cc)
    ],
)
def test_every_smuggling_vector_is_swept(char: str) -> None:
    assert unicodedata.category(char) in INVISIBLE_CATEGORIES
    assert char not in sweep(f"a{char}b")
    assert sweep(f"a{char}b") == "a b"


def test_ordinary_unicode_survives() -> None:
    for text in ["héllo", "日本語", "Việt", "🙂", "ąćęłńóśźż"]:
        assert sweep(text) == text


def test_no_normalisation_is_applied() -> None:
    """NFC and NFD are two different messages upstream. Folding them here would produce a
    locally-consistent signature the server rejects."""
    nfc, nfd = "Việt", unicodedata.normalize("NFD", "Việt")
    assert nfc != nfd
    assert sweep(nfc) != sweep(nfd)


def test_sweep_is_idempotent() -> None:
    for text in ["a\nb", "  x  ", "a‍b", "plain", "  "]:
        assert sweep(sweep(text)) == sweep(text)


def test_zwj_emoji_flattening_is_accepted_and_visible() -> None:
    """Documented trade-off upstream: mangled emoji is visible, a smuggled instruction
    is not."""
    assert sweep("👨‍👩‍👧") == "👨 👩 👧"


def test_sweep_checked_refuses_an_empty_result() -> None:
    with pytest.raises(SweepError):
        sweep_checked("​​")
    with pytest.raises(SweepError):
        sweep_checked("   ")


def test_sweep_checked_refuses_over_the_limit() -> None:
    with pytest.raises(SweepError):
        sweep_checked("a" * 4097)
    assert len(sweep_checked("a" * 4096)) == 4096


def test_is_sweep_stable() -> None:
    assert is_sweep_stable("plain text")
    assert not is_sweep_stable("a\nb")
    assert not is_sweep_stable(" padded ")


@pytest.mark.parametrize("name", ["lobby", "a", "mb-p-x9", "d-tc-contrib-abc123", "a" * 48])
def test_valid_names(name: str) -> None:
    assert valid_name(name)


@pytest.mark.parametrize(
    "name",
    ["", "-lead", "_lead", "A", "has space", "a" * 49, "has/slash", "has:colon", "café", None],
)
def test_invalid_names(name: object) -> None:
    assert not valid_name(name)


def test_room_classes_compose_by_prefix() -> None:
    assert room_classes("mb-p-secret") == {"mb-", "p-"}
    assert room_classes("e-p-x") == {"e-", "p-"}
    assert room_classes("lobby") == frozenset()
    assert room_classes("d-tc-contrib-1") == {"d-"}
    # The documented cost of the scheme: a room about e-commerce really is ephemeral.
    assert room_classes("e-commerce") == {"e-"}
