from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.crypto import didkey
from technocore_node.ledger.db import Ledger

TEST_PASSPHRASE = b"test-secret-do-not-use"


@pytest.fixture(autouse=True)
def no_outbound_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make it impossible for a unit or integration test to reach the network.

    This exists because it already happened. A test that built a real `Node` and let it
    publish a receipt sent live requests to the public Technocore instance — a shared
    service, from a test run, silently. Nothing in the test said "network"; it was three
    calls down, and the only visible symptom was the suite taking four minutes.

    A guard that lives in the test that remembers to ask for it is not a guard. This is
    autouse, and it fails loudly with the URL that was attempted, so the next such path
    is found by the person who wrote it rather than by an upstream operator.

    `tests/e2e` is exempt: it talks to a local instance on purpose, and refuses to run at
    all unless `TCN_E2E_ORIGIN` names one.
    """
    if "tests/e2e" in str(request.node.fspath).replace("\\", "/"):
        return

    async def refuse(self: object, request: Any) -> None:
        raise AssertionError(
            f"a test tried to open a real connection: {request.method} {request.url}. "
            "Stub the transport instead — the suite must never touch a live service."
        )

    # Patched on the real transport, not on the client. `httpx2.MockTransport` is a
    # different class, so a test that supplies its own responses still works; only a
    # request that would leave the machine is stopped.
    monkeypatch.setattr("httpx2.AsyncHTTPTransport.handle_async_request", refuse)


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def did(key: Ed25519PrivateKey) -> str:
    return didkey.encode_did(key.public_key())


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger(tmp_path / "state.db")


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    passfile = tmp_path / "identity.pass"
    passfile.write_bytes(TEST_PASSPHRASE)
    passfile.chmod(0o600)
    values = {
        "TCN_IDENTITY_PATH": str(tmp_path / "identity.pem"),
        "TCN_IDENTITY_PASSPHRASE_FILE": str(passfile),
        "TCN_STATE_DIR": str(tmp_path),
        "TCN_DB_PATH": str(tmp_path / "state.db"),
        "TCN_MAILBOX_ENABLED": "false",
        "TCN_WATCHER_ENABLED": "false",
        "TCN_PUBLIC_URL": "",
        "TCN_SOURCE_COMMIT": "",
    }
    for k, v in values.items():
        monkeypatch.setenv(k, v)
    for stale in ("TCN_IDENTITY_PASSPHRASE", "TCN_TECHNOCORE_ORIGIN"):
        monkeypatch.delenv(stale, raising=False)
    return values


def make_job(**overrides: Any) -> dict[str, Any]:
    job = {
        "v": "1",
        "type": "job",
        "job_id": "test-job-00000001",
        "task": "canonical_json_sha256",
        "reply_room": "mb-p-testreply",
        "input": {"value": {"b": 1, "a": [1, 2]}},
    }
    job.update(overrides)
    return job


def job_line(**overrides: Any) -> str:
    return json.dumps(
        make_job(**overrides), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
