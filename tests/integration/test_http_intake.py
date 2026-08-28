"""Signed job submission over HTTP.

The interesting tests here are not "does a valid job work". They are the ones about what a
second transport makes newly possible: a signature captured from a world-readable room
being replayed into this endpoint, a request resent verbatim, a body edited after signing,
and an endpoint that answers while the node is in no position to issue a receipt anyone
could check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from technocore_node.api import create_app
from technocore_node.config import load_settings
from technocore_node.crypto import didkey, keystore
from technocore_node.protocol.envelope import message_payload
from technocore_node.protocol.http_envelope import (
    HTTP_JOB_DOMAIN,
    body_digest,
    crosses_domains,
    http_job_payload,
    verify_http_job,
)
from technocore_node.protocol.sweep import valid_name
from technocore_node.receipts import verify_receipt
from technocore_node.service.node import Node

PASSPHRASE = b"test-secret-do-not-use"


@pytest.fixture
def requester() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    return key, didkey.encode_did(key.public_key())


@pytest.fixture
def node(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, published: list[tuple[str, dict[str, Any]]]
) -> Node:
    monkeypatch.setenv("TCN_HTTP_JOB_INTAKE_ENABLED", "true")
    monkeypatch.setenv("TCN_PUBLIC_URL", "https://example.invalid")
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    node = Node(load_settings())
    object.__setattr__(node.settings, "mailbox_enabled", True)
    # The gate: a receipt is only worth issuing if the room it will be audited in is ours.
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_observed", "1")
    node.ledger.set_state("owned_room_error", None)

    # The audit copy goes to a real room over a real socket. These tests are about the
    # intake lane, not about publishing, so the sink is recorded instead of sent — and
    # `tests/conftest.py` blocks the socket anyway, so a future test that forgets this
    # fails rather than writing to somebody's server.
    async def record(room: str, payload: dict[str, Any]) -> int | None:
        published.append((room, payload))
        return len(published)

    monkeypatch.setattr(node, "publish", record)
    return node


@pytest.fixture
def published() -> list[tuple[str, dict[str, Any]]]:
    return []


@pytest.fixture
def client(node: Node) -> TestClient:
    return TestClient(create_app(node), raise_server_exceptions=False)


def _job(job_id: str = "http-job-000001", **over: Any) -> dict[str, Any]:
    job = {
        "v": "1",
        "type": "job",
        "job_id": job_id,
        "task": "canonical_json_sha256",
        "reply_room": "mb-p-unused-over-http",
        "input": {"value": {"b": 1, "a": [1, 2]}},
    }
    job.update(over)
    return job


def _envelope(key: Ed25519PrivateKey, did: str, job: dict[str, Any], nonce: int) -> dict[str, Any]:
    return {
        "did": did,
        "sig": didkey.sign(key, http_job_payload(did, nonce, job)),
        "nonce": str(nonce),
        "job": job,
    }


# ----------------------------------------------------------- domain separation


def test_a_room_signature_cannot_be_replayed_into_this_endpoint(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    """Every signed message in a public room is world-readable.

    Without a domain tag, one of those signatures would be a valid HTTP submission from
    that key — and the key's owner never authorised a job at all. A signature means "I
    authorised *this*", and it stops meaning that the moment two different requests can
    share one.
    """
    key, did = requester
    job = _job()
    # A signature the requester made for a Technocore room, over the same bytes.
    room_sig = didkey.sign(key, message_payload("lobby", 1, json.dumps(job, sort_keys=True)))

    response = client.post("/v1/jobs", json={"did": did, "sig": room_sig, "nonce": "1", "job": job})
    assert response.status_code == 401
    assert response.json()["error"] == "bad_signature"


def test_an_http_signature_is_not_a_valid_room_message(
    requester: tuple[Ed25519PrivateKey, str],
) -> None:
    """And the reverse: one taken from here cannot be posted into a room as that key."""
    key, did = requester
    job = _job()
    http_sig = didkey.sign(key, http_job_payload(did, 1, job))

    room_payload = message_payload("lobby", 1, json.dumps(job, sort_keys=True))
    assert not didkey.verify_ok(did, http_sig, room_payload)


def test_the_two_payload_spaces_cannot_overlap() -> None:
    """No room payload can start with the tag, because no room can be named it.

    This is the whole basis of the separation, so it is asserted against the name rule
    the upstream actually enforces rather than against a hand-written example: the tag
    contains a `/`, and `NAME_RE` admits only `[a-z0-9_-]`. Should either side ever move,
    this fails here rather than somewhere a signature is accepted twice.
    """
    assert "/" in HTTP_JOB_DOMAIN
    assert not valid_name(HTTP_JOB_DOMAIN)
    assert not valid_name(HTTP_JOB_DOMAIN.split("|")[0])
    assert not crosses_domains(message_payload("lobby", 1, "anything at all"))
    assert not crosses_domains(message_payload("d-tc-contrib-abc", 99, HTTP_JOB_DOMAIN))


def test_the_domain_tag_is_version_pinned() -> None:
    """A v2 scheme gets a different tag, so a v1 signature can never satisfy it."""
    assert "/v1/" in HTTP_JOB_DOMAIN


# ------------------------------------------------------------------- the body


def test_editing_the_body_after_signing_invalidates_the_signature(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    """The nonce orders submissions; the body hash is what makes a captured one useless."""
    key, did = requester
    envelope = _envelope(key, did, _job(), 1)
    envelope["job"]["task"] = "verify_receipt_chain"  # swapped after signing

    response = client.post("/v1/jobs", json=envelope)
    assert response.status_code == 401


def test_the_signature_is_over_the_canonical_form_not_the_bytes(
    requester: tuple[Ed25519PrivateKey, str],
) -> None:
    """Two encodings of one document must verify identically.

    Otherwise a proxy that reformats JSON — or a client that orders keys differently —
    silently invalidates a request that is, by any reading, the same request.
    """
    key, did = requester
    job = _job()
    reordered = json.loads(json.dumps(dict(reversed(list(job.items())))))
    assert list(job) != list(reordered)
    assert body_digest(job) == body_digest(reordered)

    sig = didkey.sign(key, http_job_payload(did, 1, job))
    verify_http_job(did, sig, "1", reordered)


# ------------------------------------------------------------------- replay


def test_the_same_request_twice_is_refused_the_second_time(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    key, did = requester
    envelope = _envelope(key, did, _job("replay-00000001"), 100)

    assert client.post("/v1/jobs", json=envelope).status_code == 200
    second = client.post("/v1/jobs", json=envelope)
    # The idempotency check answers first, which is the friendlier of the two refusals:
    # a client retrying after a dropped response gets its receipt, not a scolding.
    assert second.status_code == 200
    assert second.json()["status"] == "already_completed"


def test_a_stale_nonce_on_new_work_is_refused(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    """A captured request cannot be reused to authorise a *different* job."""
    key, did = requester
    assert (
        client.post("/v1/jobs", json=_envelope(key, did, _job("first-000000001"), 500)).status_code
        == 200
    )

    replayed = client.post("/v1/jobs", json=_envelope(key, did, _job("second-00000001"), 499))
    assert replayed.status_code == 409
    assert replayed.json()["error"] == "nonce_not_advancing"


def test_one_requesters_nonce_is_not_anothers(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    """The counter is per key: a busy requester must not raise the floor for everyone."""
    key_a, did_a = requester
    key_b = Ed25519PrivateKey.generate()
    did_b = didkey.encode_did(key_b.public_key())

    assert (
        client.post(
            "/v1/jobs", json=_envelope(key_a, did_a, _job("a-0000000001"), 9000)
        ).status_code
        == 200
    )
    assert (
        client.post("/v1/jobs", json=_envelope(key_b, did_b, _job("b-0000000001"), 1)).status_code
        == 200
    )


def test_the_signing_payload_endpoint_tells_a_caller_the_floor(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    """So a client learns the rule from a document rather than from a 401."""
    key, did = requester
    client.post("/v1/jobs", json=_envelope(key, did, _job("floor-000000001"), 42))

    body = client.get("/v1/jobs/signing-payload", params={"did": did}).json()
    assert body["next_nonce_must_exceed"] == 42
    assert HTTP_JOB_DOMAIN in body["payload_template"]


# -------------------------------------------------------------- the gate


def test_the_endpoint_is_absent_while_the_feature_is_off(env: dict[str, str]) -> None:
    """404, not 403: a disabled lane is not a locked door to keep knocking on."""
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    node = Node(load_settings())
    assert node.settings.http_job_intake_enabled is False

    client = TestClient(create_app(node), raise_server_exceptions=False)
    response = client.post("/v1/jobs", json={"did": "x", "sig": "y", "nonce": "1", "job": {}})
    assert response.status_code == 404


def test_the_endpoint_refuses_while_the_safety_gate_is_closed(
    node: Node, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    """The same gate the mailbox lane passes.

    A receipt issued now could not be audited by anyone, so producing one would be worse
    than declining — and the refusal says why, because a caller can do nothing about a
    refusal whose shape they cannot see.
    """
    node.ledger.set_state("owned_room_owner", None)
    client = TestClient(create_app(node), raise_server_exceptions=False)
    key, did = requester

    response = client.post("/v1/jobs", json=_envelope(key, did, _job(), 1))
    assert response.status_code == 503
    assert response.json()["error"] == "not_accepting_jobs"
    assert "no owner" in response.json()["detail"]


def test_a_rate_limited_requester_does_not_spend_a_nonce(
    client: TestClient, node: Node, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    """A refusal should not cost a counter the caller then has to reason about."""
    key, did = requester
    for _ in range(node.runner.requester_jobs_per_hour):
        node.ledger.record_rejection(
            job_id=None, requester_did=did, code="not_json", detail="", request_room="http"
        )

    before = node.ledger.http_nonce_floor(did)
    response = client.post("/v1/jobs", json=_envelope(key, did, _job(), 777))
    assert response.status_code == 429
    assert node.ledger.http_nonce_floor(did) == before


# ------------------------------------------------------- the work, and its proof


def test_a_valid_job_returns_a_verifiable_receipt(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    key, did = requester
    response = client.post("/v1/jobs", json=_envelope(key, did, _job("good-00000001"), 7))
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["result"]["summary"]["canonical"] == '{"a":[1,2],"b":1}'
    assert verify_receipt(body["receipt"]) == []
    assert body["receipt_url"].endswith("/v1/receipts/good-00000001")


def test_the_receipt_is_retrievable_at_the_url_it_advertises(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    key, did = requester
    client.post("/v1/jobs", json=_envelope(key, did, _job("fetch-000000001"), 8))

    fetched = client.get("/v1/receipts/fetch-000000001").json()
    assert fetched["status"] == "completed"
    assert verify_receipt(fetched["receipt"]) == []


@pytest.mark.parametrize(
    ("job", "expected"),
    [
        (_job(task="rm -rf /"), "schema_invalid"),
        (
            _job(task="protocol_manifest_snapshot", input={"url": "http://169.254.169.254/"}),
            "input_invalid",
        ),
        (_job(reply_room="lobby"), "reply_room_not_allowed"),
        (_job(job_id="short"), "schema_invalid"),
    ],
)
def test_the_http_lane_refuses_everything_the_mailbox_lane_does(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str], job: dict[str, Any], expected: str
) -> None:
    """One validator, one task registry, one set of refusals.

    Duplicating a security-relevant pipeline per transport is how the two copies drift
    apart, and the one nobody is looking at is the one that lets something through.
    """
    key, did = requester
    response = client.post("/v1/jobs", json=_envelope(key, did, job, 3000))
    assert response.status_code == 400
    assert response.json()["error"] == expected


def test_an_oversized_body_is_refused_before_it_is_parsed(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    key, did = requester
    envelope = _envelope(key, did, _job(), 1)
    envelope["padding"] = "x" * 20_000
    response = client.post("/v1/jobs", content=json.dumps(envelope))
    assert response.status_code == 413


@pytest.mark.parametrize(
    "envelope",
    [
        {},
        {"did": "x"},
        {"did": "x", "sig": "y", "nonce": "1"},
        {"did": "x", "sig": "y", "nonce": 1, "job": {}},
        {"did": "x", "sig": "y", "nonce": "1", "job": "not an object"},
    ],
)
def test_a_malformed_envelope_is_refused(client: TestClient, envelope: dict[str, Any]) -> None:
    response = client.post("/v1/jobs", json=envelope)
    assert response.status_code == 400
    assert response.json()["error"] in {"malformed_envelope", "not_an_object"}


def test_the_endpoint_leaks_nothing_about_the_host(
    client: TestClient, requester: tuple[Ed25519PrivateKey, str]
) -> None:
    key, did = requester
    bodies = [
        client.post("/v1/jobs", json=_envelope(key, did, _job(), 1)).text,
        client.post("/v1/jobs", json={"bad": True}).text,
        client.get("/v1/jobs/signing-payload", params={"did": did}).text,
    ]
    for body in bodies:
        lowered = body.lower()
        for forbidden in ("/etc/", "/var/lib/", "/home/", "traceback", "passphrase", "sqlite"):
            assert forbidden not in lowered, f"{forbidden!r} leaked"


def test_the_audit_copy_goes_to_the_room_the_gate_checked(
    client: TestClient,
    node: Node,
    requester: tuple[Ed25519PrivateKey, str],
    published: list[tuple[str, dict[str, Any]]],
) -> None:
    """A receipt earned over HTTP is auditable in the same room as one earned in a room.

    The gate's promise is that a receipt this node issues can be checked against a room
    this node owns. That promise is only kept if the copy actually goes there, so the
    destination is asserted rather than assumed — the two lanes must not diverge into one
    auditable and one not.
    """
    key, did = requester
    body = _envelope(key, did, _job("audited-00001"), 7)

    assert client.post("/v1/jobs", json=body).status_code == 200

    rooms = [room for room, _ in published]
    assert rooms == [node.result_room]
    assert published[0][1]["job_id"] == "audited-00001"
    assert published[0][1]["type"] == "receipt"
