"""Secret isolation, SSRF containment, and the things the tasks must refuse.

These are the tests that would catch the failures nobody notices until it is too late: a
key readable by the wrong user, a passphrase in a log line, an outbound request steered by
a stranger.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from technocore_node.config import ALLOWED_ORIGINS, ConfigError, load_settings
from technocore_node.crypto import keystore
from technocore_node.jobs.tasks import REGISTRY, TaskError
from technocore_node.logging import JsonFormatter, redact
from technocore_node.protocol.client import TechnocoreClient, TechnocoreError

PASSPHRASE = b"test-secret-do-not-use"


# ------------------------------------------------------------------ key custody


def test_a_generated_key_is_mode_600(tmp_path: Path) -> None:
    path = tmp_path / "identity.pem"
    keystore.generate(path, PASSPHRASE)
    assert oct(path.stat().st_mode)[-3:] == "600"


def test_the_key_file_is_encrypted_on_disk(tmp_path: Path) -> None:
    path = tmp_path / "identity.pem"
    keystore.generate(path, PASSPHRASE)
    body = path.read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in body
    assert b"BEGIN PRIVATE KEY" not in body


def test_loading_without_the_passphrase_fails(tmp_path: Path) -> None:
    path = tmp_path / "identity.pem"
    keystore.generate(path, PASSPHRASE)
    with pytest.raises(keystore.KeystoreError):
        keystore.load(path, None)
    with pytest.raises(keystore.KeystoreError):
        keystore.load(path, b"wrong-passphrase")


def test_a_group_readable_key_is_refused(tmp_path: Path) -> None:
    """A key anyone else can read has to be treated as disclosed, so it fails closed."""
    path = tmp_path / "identity.pem"
    keystore.generate(path, PASSPHRASE)
    path.chmod(0o640)
    with pytest.raises(keystore.KeystoreError, match="disclosed"):
        keystore.load(path, PASSPHRASE)


def test_an_existing_key_is_never_silently_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "identity.pem"
    first = keystore.generate(path, PASSPHRASE)
    with pytest.raises(keystore.KeystoreError, match="orphan"):
        keystore.generate(path, PASSPHRASE)
    assert keystore.load(path, PASSPHRASE).did == first.did


def test_an_unencrypted_key_is_refused_at_creation(tmp_path: Path) -> None:
    with pytest.raises(keystore.KeystoreError, match="passphrase"):
        keystore.generate(tmp_path / "identity.pem", None)


def test_a_backup_restores_the_same_did(tmp_path: Path) -> None:
    path = tmp_path / "identity.pem"
    identity = keystore.generate(path, PASSPHRASE)
    assert keystore.verify_restores_same_did(path.read_bytes(), PASSPHRASE, identity.did)
    assert not keystore.verify_restores_same_did(path.read_bytes(), b"wrong", identity.did)
    assert not keystore.verify_restores_same_did(b"garbage", PASSPHRASE, identity.did)


def test_the_identity_object_does_not_print_the_key(tmp_path: Path) -> None:
    identity = keystore.generate(tmp_path / "identity.pem", PASSPHRASE)
    rendered = repr(identity)
    assert "PRIVATE KEY" not in rendered
    assert PASSPHRASE.decode() not in rendered


# ------------------------------------------------------------------- redaction


def test_pem_bodies_are_redacted_from_logs() -> None:
    # secret-scan: allow — a fake PEM is the input this test exists to redact.
    leaked = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQ\n-----END PRIVATE KEY-----"
    assert "MC4CAQAwBQ" not in redact(leaked)


@pytest.mark.parametrize(
    "line",
    [
        "passphrase=hunter2",
        "password: hunter2",
        "api_key=abcdef123456",  # secret-scan: allow — a fixture, not a key
        "TOKEN: ghp_xxxxxxxxxxxx",
    ],
)
def test_credential_shaped_values_are_redacted(line: str) -> None:
    assert "hunter2" not in redact(line)
    assert "abcdef123456" not in redact(line)
    assert "ghp_xxxxxxxxxxxx" not in redact(line)


def test_the_formatter_redacts_structured_fields() -> None:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "starting", None, None)
    record.fields = {"config": "passphrase=hunter2"}  # type: ignore[attr-defined]
    emitted = json.loads(JsonFormatter().format(record))
    assert "hunter2" not in json.dumps(emitted)


# ----------------------------------------------------------------------- SSRF


def test_the_upstream_origin_is_allowlisted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TCN_TECHNOCORE_ORIGIN", "https://attacker.example")
    with pytest.raises(ConfigError, match="allowlist"):
        load_settings()


@pytest.mark.parametrize(
    "origin",
    [
        "http://169.254.169.254",
        "http://localhost:5432",
        "file:///etc/passwd",
        "https://technocore.chat.attacker.example",
        "https://technocore.chat@attacker.example",
    ],
)
def test_the_client_refuses_a_non_allowlisted_origin(origin: str) -> None:
    with pytest.raises(TechnocoreError, match="allowlisted"):
        TechnocoreClient(origin)


def test_the_allowlist_is_small_and_explicit() -> None:
    assert {"https://technocore.chat", "http://127.0.0.1:8080"} == ALLOWED_ORIGINS


async def test_the_client_refuses_a_malformed_room_name() -> None:
    client = TechnocoreClient("https://technocore.chat")
    try:
        for room in ["../kv/did", "Room", "a" * 49, "room name"]:
            with pytest.raises(TechnocoreError, match="invalid"):
                await client.read_room(room)
    finally:
        await client.aclose()


# ---------------------------------------------------------------- task refusals


class StubContext:
    def latest_protocol_snapshot(self) -> dict[str, object] | None:
        return {"captured_at": "2026-01-01T00:00:00Z"}

    def receipt_chain_for(self, job_id: str) -> list[dict[str, object]]:
        return []


def test_no_task_can_reach_the_network_or_the_filesystem() -> None:
    """The registry is the executable surface. If a task ever grows a fetch or an open,
    this is the test that should stop it."""
    import inspect

    for name, fn in REGISTRY.items():
        source = inspect.getsource(fn)
        for forbidden in (
            "httpx",
            "requests",
            "urlopen",
            "subprocess",
            "os.system",
            "eval(",
            "exec(",
            "__import__",
            "open(",
        ):
            assert forbidden not in source, f"{name} references {forbidden}"


def test_the_snapshot_task_reports_stored_state_only() -> None:
    result = REGISTRY["protocol_manifest_snapshot"]({}, StubContext())
    assert result["captured_at"] == "2026-01-01T00:00:00Z"


def test_verify_receipt_chain_refuses_an_unknown_job_id() -> None:
    with pytest.raises(TaskError, match="no receipt"):
        REGISTRY["verify_receipt_chain"]({"job_id": "no-such-job-01"}, StubContext())


def test_signature_task_flags_the_classic_pre_sweep_mistake() -> None:
    """The single most common protocol error: signing the text you typed rather than the
    text that survives the sweep. The task names it instead of just saying `false`."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from technocore_node.crypto import didkey

    key = Ed25519PrivateKey.generate()
    did = didkey.encode_did(key.public_key())
    raw_text = "  hello\nworld  "
    sig = didkey.sign(key, f"lobby|5|{raw_text}")  # signed BEFORE the sweep — the mistake

    report = REGISTRY["verify_technocore_signature"](
        {"room": "lobby", "nonce": "5", "text": raw_text, "did": did, "sig": sig},
        StubContext(),
    )
    assert report["valid"] is False
    assert report["checks"]["text_is_sweep_stable"] is False
    assert report["checks"]["signed_pre_sweep_text"] is True


def test_signature_task_accepts_a_correctly_signed_envelope() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from technocore_node.crypto import didkey
    from technocore_node.protocol.envelope import message_payload

    key = Ed25519PrivateKey.generate()
    did = didkey.encode_did(key.public_key())
    text = "hello world"
    sig = didkey.sign(key, message_payload("lobby", 5, text))

    report = REGISTRY["verify_technocore_signature"](
        {"room": "lobby", "nonce": "5", "text": text, "did": did, "sig": sig}, StubContext()
    )
    assert report["valid"] is True
    assert all(report["checks"].values())
