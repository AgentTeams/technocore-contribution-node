"""The public API — what it answers, and what it must never leak."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from technocore_node.api import create_app
from technocore_node.config import load_settings
from technocore_node.crypto import keystore
from technocore_node.service.node import Node

PASSPHRASE = b"test-secret-do-not-use"


@pytest.fixture
def client(env: dict[str, str], tmp_path: Path) -> TestClient:
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    settings = load_settings()
    node = Node(settings)
    return TestClient(create_app(node), raise_server_exceptions=False)


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readyz(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["checks"] == {"ledger": True, "identity": True}


def test_info_exposes_the_public_identity_only(client: TestClient) -> None:
    info = client.get("/v1/info").json()
    assert info["did"].startswith("did:key:z6Mk")
    assert info["public_mailbox"].startswith("mb-tc-jobs-")
    assert info["result_room"].startswith("d-tc-contrib-")
    assert "security_model" in info


def test_capabilities_lists_four_tasks_and_the_refusals(client: TestClient) -> None:
    caps = client.get("/v1/capabilities").json()
    assert len(caps["tasks"]) == 4
    assert caps["limits"]["reply_room_classes"] == ["p-", "mb-p-", "e-p-"]
    joined = " ".join(caps["refuses"])
    assert "shell" in joined and "URL" in joined


def test_metrics_report_an_honest_zero(client: TestClient) -> None:
    metrics = client.get("/v1/metrics").json()
    assert metrics["third_party"]["total_jobs"] == 0
    assert metrics["third_party"]["independent_requester_dids"] == 0
    assert metrics["third_party"]["completion_rate"] is None
    assert metrics["latency_ms"]["p50"] is None, "no fabricated latency with no jobs"
    assert metrics["internal_test"]["jobs"] == 0


def test_openapi_is_served(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert spec["openapi"].startswith("3.")
    assert "/v1/receipts/{job_id}" in spec["paths"]


def test_the_dashboard_renders(client: TestClient) -> None:
    page = client.get("/")
    assert page.status_code == 200
    body = page.text
    assert "Technocore Contribution Node" in body
    assert "No third party has used this node yet" in body
    assert "http://" not in body.replace("http://www.w3.org", ""), "no external asset hosts"


def test_an_unknown_receipt_is_a_404(client: TestClient) -> None:
    assert client.get("/v1/receipts/no-such-job-here").status_code == 404


def test_a_malformed_job_id_is_a_400(client: TestClient) -> None:
    assert client.get("/v1/receipts/../../etc/passwd").status_code in {400, 404}
    assert client.get("/v1/receipts/short").status_code == 400


def test_no_response_leaks_a_secret_or_a_host_path(client: TestClient) -> None:
    """The whole point of a read-only surface is that reading it teaches you nothing about
    the host it runs on."""
    bodies = [
        client.get(path).text
        for path in (
            "/",
            "/v1/info",
            "/v1/capabilities",
            "/v1/metrics",
            "/v1/protocol-status",
            "/v1/schemas",
            "/openapi.json",
            "/readyz",
        )
    ]
    for body in bodies:
        lowered = body.lower()
        for forbidden in (
            "private key",
            "passphrase",
            "/etc/",
            "/var/lib/",
            "/home/",
            "begin ",
            "traceback",
            "sqlite",
            ".env",
        ):
            assert forbidden not in lowered, f"{forbidden!r} leaked into a response"


def test_the_protocol_schemas_are_published(client: TestClient) -> None:
    schemas = client.get("/v1/schemas").json()
    assert schemas["job"]["properties"]["task"]["enum"]
    assert schemas["job"]["additionalProperties"] is False
    assert schemas["receipt"]["properties"]["request_seq"]["description"].startswith(
        "Server-assigned"
    )


def test_protocol_status_says_unknown_before_a_capture(client: TestClient) -> None:
    assert client.get("/v1/protocol-status").json()["status"] == "unknown"


def test_a_receipt_is_served_once_recorded(client: TestClient, env: dict[str, str]) -> None:
    from technocore_node.ledger.db import Ledger

    ledger = Ledger(env["TCN_DB_PATH"])
    # A receipt without its job row is refused by a foreign key, on purpose: a receipt
    # that refers to work with no record is not evidence of anything.
    ledger.insert_job(
        job_id="served-job-0001",
        protocol_version="1",
        requester_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        provider_did="did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
        request_room="mb-tc-jobs-abc",
        reply_room="mb-p-reply",
        request_seq=1,
        request_hash="sha256:" + "0" * 64,
        task_type="canonical_json_sha256",
        status="completed",
        internal_test=False,
    )
    receipt = {
        "v": "1",
        "type": "receipt",
        "receipt_id": "rcpt-abcdef123456",
        "job_id": "served-job-0001",
        "requester_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "provider_did": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
        "request_hash": "sha256:" + "0" * 64,
        "result_hash": "sha256:" + "1" * 64,
        "provider_signature": "b" * 86,
        "sig": "a" * 86,
        "receipt_hash": "sha256:" + "2" * 64,
        "created_at": "2026-08-27T00:00:00Z",
    }
    ledger.record_receipt(receipt, json.dumps(receipt), internal_test=False)
    ledger.record_receipt_reply_seq("served-job-0001", 12)

    body = client.get("/v1/receipts/served-job-0001").json()
    assert body["status"] == "completed"
    assert body["reply_room_seq"] == 12
    assert body["receipt"]["job_id"] == "served-job-0001"
    # No owned-room copy was recorded, so the receipt is not yet checkable by anyone but
    # the requester — and the API says so rather than presenting it as fully published.
    assert body["audit_room_seq"] is None
    assert body["publicly_auditable"] is False


def test_a_rejected_job_is_explained_by_a_read_not_a_reply(
    client: TestClient, env: dict[str, str]
) -> None:
    """A refused requester learns why through a read they initiate — never through a
    message this node is steered into posting."""
    from technocore_node.ledger.db import Ledger

    Ledger(env["TCN_DB_PATH"]).record_rejection(
        job_id="refused-job-0001",
        requester_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        code="reply_room_not_allowed",
        detail="reply_room must be an unlisted room: p- or mb-p-",
        request_room="mb-tc-jobs-abc",
    )
    body = client.get("/v1/receipts/refused-job-0001").json()
    assert body["status"] == "rejected"
    assert body["failure_code"] == "reply_room_not_allowed"


def test_a_receipt_without_its_job_is_refused(env: dict[str, str]) -> None:
    """The ledger will not hold a receipt that points at work it has no record of."""
    import sqlite3

    from technocore_node.ledger.db import Ledger

    orphan = {
        "receipt_id": "rcpt-orphan00001",
        "job_id": "no-such-job-0001",
        "requester_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "provider_did": "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
        "request_hash": "sha256:" + "0" * 64,
        "result_hash": "sha256:" + "1" * 64,
        "provider_signature": "b" * 86,
        "sig": "a" * 86,
        "receipt_hash": "sha256:" + "2" * 64,
        "created_at": "2026-08-27T00:00:00Z",
    }
    with pytest.raises(sqlite3.IntegrityError):
        Ledger(env["TCN_DB_PATH"]).record_receipt(orphan, json.dumps(orphan), internal_test=False)
