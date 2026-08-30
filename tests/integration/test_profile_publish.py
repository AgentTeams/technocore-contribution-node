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

import hashlib
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
            else:
                # Cleared explicitly. Runs in one test share a state directory, so
                # "did not set it" is not the same as "it is not set" — and a test that
                # passes on leftovers from the run before it is not testing this one.
                self.ledger.set_state("owned_room_owner", None)
                self.ledger.set_state("owned_room_observed", None)
                self.ledger.set_state("owned_room_renewed", None)

        async def observe_reachability(self) -> None:
            return None

        async def publish_reporting(
            self, room: str, payload: dict[str, Any]
        ) -> tuple[int | None, str]:
            if behaviour.get("sink_refuses"):
                # What `Node.publish_reporting` does when ownership stops being confirmed
                # between the caller's check and the write: nothing is sent, and it says
                # so rather than leaving the caller to infer it.
                if not behaviour.get("recovers_after"):
                    self.ledger.set_state("owned_room_owner", None)
                return None, "refused_locally"
            captured["payload"] = payload
            forced = behaviour.get("publish_outcome")
            if forced:
                self.ledger.set_state(
                    f"last_publish_error:{room}", behaviour.get("error", "upstream said no")
                )
                return None, forced
            if behaviour.get("publish_fails"):
                self.ledger.set_state(
                    f"last_publish_error:{room}", behaviour.get("error", "HTTP 503")
                )
                if behaviour.get("lapses_after"):
                    # The lease dies after the request went out. That is a separate fact
                    # from the request's fate, and must not rewrite it.
                    self.ledger.set_state("owned_room_owner", None)
                return None, "unconfirmed"
            return 7, "published"

    async def set_note(self: Any, ns: str, key: str, value: str) -> None:
        captured["note"] = value
        loaded = json.loads(value)
        captured["did"] = loaded["did"]
        captured["hash"] = "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

    async def read_room(self: Any, room: str, **kw: Any) -> dict[str, Any]:
        if behaviour.get("room_fails"):
            raise cli.TechnocoreError(behaviour["room_fails"])
        build = behaviour.get("room")
        return build(captured["did"], captured["hash"]) if build else _room()

    monkeypatch.setattr(cli, "Node", Node)
    monkeypatch.setattr("technocore_node.protocol.client.TechnocoreClient.set_note", set_note)
    monkeypatch.setattr("technocore_node.protocol.client.TechnocoreClient.read_room", read_room)

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


def test_an_unconfirmed_attestation_is_not_reported_as_a_failed_one(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """The case that read as two nulls — and the trap in fixing it.

    "It failed" is as much a false certainty as silence was. The write may have landed:
    on 2026-08-30 one reported as a 503 was in the room afterwards. So the third state is
    *unknown*, and `profile_is_verifiable` is None rather than False, because False is a
    claim about the room that nobody made.
    """
    out = _run(monkeypatch, args, publish_fails=True, error="HTTP 503: Service Unavailable")

    assert out["attestation_seq"] is None
    assert out["profile_is_verifiable"] is None
    assert out["attestation_refused"] is not None
    assert "NOT confirmed" in out["attestation_refused"]
    assert "503" in out["attestation_refused"]
    assert "may have landed" in out["attestation_refused"]
    # And it says the safe way out, rather than leaving the reader to invent one.
    assert "re-run" in out["attestation_refused"].lower()


def test_the_three_states_are_three_different_values(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """Confirmed, deliberately not written, and unknown. None may collapse into another."""
    landed = _run(monkeypatch, args)
    refused = _run(monkeypatch, args, owned=False)
    unknown = _run(monkeypatch, args, publish_fails=True)

    assert landed["profile_is_verifiable"] is True
    assert refused["profile_is_verifiable"] is False
    assert unknown["profile_is_verifiable"] is None


def test_a_deliberate_refusal_is_still_distinguishable(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """Not written on purpose, and written-but-lost, must not read the same."""
    out = _run(monkeypatch, args, owned=False)

    assert out["attestation_seq"] is None
    assert out["profile_is_verifiable"] is False
    assert out["attestation_already_present"] is None  # the room was never read
    assert "not confirmed as owned" in out["attestation_refused"]
    assert "NOT confirmed" not in out["attestation_refused"]
    # Nothing was sent to the room at all.
    assert "payload" not in out["_captured"]


def test_the_note_is_published_in_every_case(monkeypatch: pytest.MonkeyPatch, args: Any) -> None:
    """The note is not the risky write; withholding it would help nobody."""
    for behaviour in ({}, {"publish_fails": True}, {"owned": False}):
        out = _run(monkeypatch, args, **behaviour)
        assert json.loads(out["_captured"]["note"])["did"] == out["profile"]["did"]


# ------------------------------------------------ not twice, if it can help it


def _room(*messages: dict[str, Any]) -> dict[str, Any]:
    return {"messages": list(messages), "count": len(messages), "last_seq": len(messages)}


def _attestation(did: str, profile_hash: str, seq: int = 1) -> dict[str, Any]:
    return {
        "seq": seq,
        "from": did,
        "text": json.dumps(
            {
                "v": "1",
                "type": "profile_attestation",
                "did": did,
                "note": "/kv/did-xx/yyy",
                "profile_sha256": profile_hash,
            }
        ),
    }


def test_an_already_attested_profile_is_not_attested_again(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """Re-running is how an operator recovers a failed attestation. It must be safe.

    Without this it is also how they produce a second one — which is how the room came to
    hold two identical attestations on 2026-08-30, after a `503` was reported for a write
    that had in fact landed.
    """
    out = _run(monkeypatch, args, room=lambda did, h: _room(_attestation(did, h, seq=4)))

    assert out["attestation_seq"] == 4
    assert out["profile_is_verifiable"] is True
    assert out["attestation_already_present"] is True
    # Nothing was written to the room.
    assert "payload" not in out["_captured"]


def test_a_different_profile_is_attested_even_if_an_older_one_is_there(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """The guard is per profile hash. A changed profile needs its own attestation."""
    out = _run(
        monkeypatch, args, room=lambda did, h: _room(_attestation(did, "sha256:" + "0" * 64))
    )

    assert out["attestation_already_present"] is False
    assert out["_captured"]["payload"]["profile_sha256"] == out["profile_sha256"]


def test_a_strangers_copy_of_our_hash_does_not_count(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """The room is world-readable. Anyone can repeat our hash; only our key can sign it.

    Matching on the hash alone would let a stranger's message suppress the attestation
    that makes the profile verifiable — a denial of exactly the thing being published.
    """
    other = "did:key:z6MkfyqMqvC4QGbyMAzpL4haXspn1f1ZGUwhdPearjqPpnnc"
    out = _run(monkeypatch, args, room=lambda did, h: _room(_attestation(other, h, seq=3)))

    assert out["attestation_already_present"] is False
    assert out["_captured"]["payload"]["type"] == "profile_attestation"


def test_an_unreadable_room_defers_rather_than_writing_blind(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """Writing on an unknown answer is the mistake this exists to stop.

    A failed read means "already attested?" has no answer. The note is published either
    way, so deferring costs a re-run and risks nothing; writing risks the duplicate.
    """
    out = _run(monkeypatch, args, room_fails="HTTP 503: Service Unavailable")

    assert out["attestation_seq"] is None
    # Nothing was written, so this one really is False rather than unknown.
    assert out["profile_is_verifiable"] is False
    # But no absence was observed, so the guard reports None rather than claiming one.
    assert out["attestation_already_present"] is None
    assert "could not be read" in out["attestation_refused"]
    assert "503" in out["attestation_refused"]
    assert "re-run" in out["attestation_refused"]
    assert "payload" not in out["_captured"]


def test_a_room_message_that_is_json_but_not_an_object_does_not_crash(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """`[]`, `null` and `"x"` are all valid JSON and none of them has `.get`.

    Anyone can post into a room this node reads. A message that parses is still only a
    string a stranger chose, and crashing on one would abort the command after the note
    was published — leaving it unverifiable, with the traceback as the only report.
    """
    bodies = ["[]", "null", '"just a string"', "not json at all", "123", '{"a":' * 40]

    def room(did: str, profile_hash: str) -> dict[str, Any]:
        # Under OUR did as well as a stranger's: a body is only reached after the signer
        # matches, so stranger-signed junk never exercises the parse at all.
        ours = [{"seq": i, "from": did, "text": b} for i, b in enumerate(bodies, start=1)]
        theirs = [
            {"seq": 20 + i, "from": "did:key:zStranger", "text": b} for i, b in enumerate(bodies)
        ]
        return _room(*ours, *theirs, {"seq": 40, "from": did, "text": '{"type":"receipt"}'})

    out = _run(monkeypatch, args, room=room)

    # It read past all of them and attested normally.
    assert out["attestation_seq"] == 7
    assert out["profile_is_verifiable"] is True


def test_a_match_with_an_unusable_seq_is_still_a_match(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """The envelope is untrusted like everything else in the room.

    Treating a match whose `seq` is a string as *absent* would write a second attestation
    on the strength of a malformed field — the duplicate this guard exists to prevent,
    reached by another route. Presence and the number are two answers.
    """
    for bad in ("4", None, -1, 0, True, 1.5):

        def room(did: str, h: str, bad: Any = bad) -> dict[str, Any]:
            message = _attestation(did, h)
            message["seq"] = bad
            return _room(message)

        out = _run(monkeypatch, args, room=room)

        assert out["attestation_already_present"] is True, bad
        assert out["profile_is_verifiable"] is True, bad
        assert out["attestation_seq"] is None, bad
        assert "payload" not in out["_captured"], bad


def test_a_sink_refusal_is_not_reported_as_a_lost_write(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """Nothing left the machine, so "it may have landed" would be an unobserved claim.

    `publish` has its own guard: ownership or the lease can stop being confirmed between
    the check here and the write there. That is a deliberate local refusal, not a write
    whose fate is unknown, and collapsing it into the unknown state is the same error
    this release is about — made one layer down.
    """
    out = _run(monkeypatch, args, sink_refuses=True)

    assert out["attestation_seq"] is None
    assert out["profile_is_verifiable"] is False
    assert "was not sent" in out["attestation_refused"]
    assert "may have landed" not in out["attestation_refused"]
    assert "payload" not in out["_captured"]
    # And it did not have to read mutable state back to know that.
    assert "stopped being confirmed" in out["attestation_refused"]


def test_the_reason_comes_from_the_write_not_from_reading_state_back(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """Ownership recovering after a real refusal must not turn it into "may have landed".

    Inferring the reason by re-reading `owns_result_room()` after the fact is a guess, and
    it can be wrong in both directions — ownership can lapse between a real send and the
    re-read, or recover between a local refusal and it. `publish_reporting` knows which
    happened at the point it happens, so this asserts the report survives the state moving
    afterwards.
    """
    out = _run(monkeypatch, args, sink_refuses=True, recovers_after=True)

    assert out["profile_is_verifiable"] is False
    assert "was not sent" in out["attestation_refused"]
    assert "may have landed" not in out["attestation_refused"]


def test_an_unconfirmed_write_stays_unconfirmed_even_if_ownership_lapses_after(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """The other direction. The request went out; losing the lease afterwards is separate."""
    out = _run(monkeypatch, args, publish_fails=True, lapses_after=True)

    assert out["profile_is_verifiable"] is None
    assert "NOT confirmed" in out["attestation_refused"]
    assert "may have landed" in out["attestation_refused"]


def test_a_dry_run_concludes_nothing_because_it_observed_nothing(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """`false` would be a claim about a room this run never looked at."""
    args.dry_run = True
    out = _run(monkeypatch, args)

    assert out["dry_run"] is True
    assert out["profile_is_verifiable"] is None
    assert out["attestation_already_present"] is None
    assert out["attestation_seq"] is None
    assert "note" not in out["_captured"]
    assert "payload" not in out["_captured"]


def test_a_duplicate_refusal_is_not_treated_as_proof_of_presence(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """It says an identical text was accepted recently — counted by text, not by sender.

    A stranger posting the same JSON produces it, and it says nothing about whether this
    node's signed copy is in the room now. Reporting it as verifiable made a claim anyone
    could arrange, which is a guard a third party can satisfy.
    """
    out = _run(monkeypatch, args, publish_outcome="unconfirmed", error="422 duplicate")

    assert out["profile_is_verifiable"] is None
    assert out["attestation_already_present"] is False
    assert "NOT confirmed" in out["attestation_refused"]


def test_an_invalid_room_name_is_refused_before_anything_is_sent(
    monkeypatch: pytest.MonkeyPatch, args: Any
) -> None:
    """`say_signed` would raise for this before sending, which is a refusal, not a loss."""
    out = _run(monkeypatch, args, publish_outcome="bad_room")

    assert out["profile_is_verifiable"] is False
    assert "was not sent" in out["attestation_refused"]
    assert "may have landed" not in out["attestation_refused"]
