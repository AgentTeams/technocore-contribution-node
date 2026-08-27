from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.crypto import didkey
from technocore_node.ledger.db import Ledger

TEST_PASSPHRASE = b"test-secret-do-not-use"


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
