"""`publish-profile` has to say which of three things happened.

The note and the attestation are two writes with different meanings. The note is the
profile; the attestation is the only thing that makes it *this node's* profile, because
the note namespace is world-writable and anyone can put anything there under any key.

So there are three outcomes, and they are not interchangeable:

* published — the note is up and the signed copy in the owned room vouches for it;
* refused — ownership was not confirmed, so nothing was written to the room on purpose;
* attempted and lost — the write was made and did not land.

The third was reported as two nulls, which reads like the second read like nothing at all.
An operator seeing `attestation_seq: null, attestation_refused: null` after a 503 would
have had no way to tell a deliberate refusal from a silent failure, and the published note
would sit there unverifiable with nothing saying so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from technocore_node.cli import main as cli
from technocore_node.crypto import keystore
from technocore_node.ledger.db import utcnow

PASSPHRASE = b"test-secret-do-not-use"


@pytest.fixture
def args(env: dict[str, str]) -> Any:
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    return type("Args", (), {"dry_run": False, "force": False})()


def _run(monkeypatch: pytest.MonkeyPatch, args: Any, **behaviour: Any) -> dict[str, Any]:
    """Run the command against a node whose room writes do what `behaviour` says."""
    captured: dict[str, Any] = {}
    real_node = cli.Node

    class Node(real_node):  # type: ignore[misc, valid-type]
        def __init__(self, *a: Any, **k: Any) -> None:
            super().__init__(*a, **k)
            if behaviour.get("owned", True):
                self.ledger.set_state("owned_room_owner", self.did)
                self.ledger.set_state("owned_room_observed", "1")
                self.ledger.set_state("owned_room_error", None)
                self.ledger.set_state("owned_room_renewed", utcnow())

        async def observe_reachability(self) -> None:
            return None

        async def publish(self, room: str, payload: dict[str, Any]) -> int | None:
            captured["payload"] = payload
            if behaviour.get("publish_fails"):
                self.ledger.set_state(
                    f"last_publish_error:{room}", behaviour.get("error", "HTTP 503")
                )
                return None
            return 7

    async def set_note(self: Any, ns: str, key: str, value: str) -> None:
        captured["note"] = value

    monkeypatch.setattr(cli, "Node", Node)
    monkeypatch.setattr("technocore_node.protocol.client.TechnocoreClient.set_note", set_note)

    printed: list[Any] = []
    monkeypatch.setattr(cli, "_emit", printed.append)
    cli.cmd_publish_profile(args)
    result: dict[str, Any] = printed[0]
    result["_captured"] = captured
    return result


def test_a_landed_attestation_is_reported_as_verifiable(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    out = _run(monkeypatch, args)

    assert out["attestation_seq"] == 7
    assert out["attestation_refused"] is None
    assert out["profile_is_verifiable"] is True
    assert out["_captured"]["payload"]["type"] == "profile_attestation"
    assert out["_captured"]["payload"]["profile_sha256"] == out["profile_sha256"]


def test_an_attestation_that_did_not_land_says_so_and_says_why(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """The case that read as two nulls. It is the one an operator most needs to see."""
    out = _run(monkeypatch, args, publish_fails=True, error="HTTP 503: Service Unavailable")

    assert out["attestation_seq"] is None
    assert out["profile_is_verifiable"] is False
    assert out["attestation_refused"] is not None
    assert "did not land" in out["attestation_refused"]
    assert "503" in out["attestation_refused"]
    # And it says what that costs, rather than leaving the reader to work it out.
    assert "unverifiable" in out["attestation_refused"]


def test_a_deliberate_refusal_is_still_distinguishable(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """Not written on purpose, and written-but-lost, must not read the same."""
    out = _run(monkeypatch, args, owned=False)

    assert out["attestation_seq"] is None
    assert out["profile_is_verifiable"] is False
    assert "not confirmed as owned" in out["attestation_refused"]
    assert "did not land" not in out["attestation_refused"]
    # Nothing was sent to the room at all.
    assert "payload" not in out["_captured"]


def test_the_note_is_published_in_every_case(monkeypatch: pytest.MonkeyPatch, args: Any) -> None:
    """The note is not the risky write; withholding it would help nobody."""
    for behaviour in ({}, {"publish_fails": True}, {"owned": False}):
        out = _run(monkeypatch, args, **behaviour)
        assert json.loads(out["_captured"]["note"])["did"] == out["profile"]["did"]
