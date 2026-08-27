"""Operator commands.

Every command that touches the network or the key is explicit and one-shot. Nothing here
runs on a schedule, and nothing posts to a shared room without being told to — publishing
is an operator decision, not something a tool does on the way past.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import load_settings
from ..crypto import didkey, keystore
from ..ledger.db import Ledger
from ..logging import configure, get_logger
from ..protocol.client import TechnocoreClient
from ..service.node import Node
from ..service.rooms import mailbox_room, result_room

log = get_logger(__name__)


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _passphrase_from(path: str | None) -> bytes | None:
    if path:
        return Path(path).read_bytes().strip() or None
    settings = load_settings()
    return settings.passphrase()


# ------------------------------------------------------------------- commands


def cmd_keygen(args: argparse.Namespace) -> int:
    """Create the node's single production identity."""
    settings = load_settings()
    path = Path(args.path or settings.identity_path)
    passphrase = _passphrase_from(args.passphrase_file)
    if not passphrase:
        print(
            "refusing to create an unencrypted key: set TCN_IDENTITY_PASSPHRASE_FILE "
            "to a 0600 file holding the passphrase",
            file=sys.stderr,
        )
        return 2
    identity = keystore.generate(path, passphrase, overwrite=args.force)
    _emit(
        {
            "did": identity.did,
            "fingerprint": identity.fingerprint,
            "public_key_sha256": identity.public_key_hash,
            "mailbox": mailbox_room(identity.did),
            "result_room": result_room(identity.did),
            "key_path": str(path),
            "note": "The private key never leaves this file. Back it up encrypted, and do "
            "not rotate it: every published receipt points at this DID.",
        }
    )
    return 0


def cmd_did(args: argparse.Namespace) -> int:
    """Print the node's public identity. Never touches the network."""
    settings = load_settings()
    identity = keystore.load(
        Path(args.path or settings.identity_path), _passphrase_from(args.passphrase_file)
    )
    _emit(
        {
            "did": identity.did,
            "fingerprint": identity.fingerprint,
            "abbreviated": didkey.abbreviate(identity.did),
            "public_key_sha256": identity.public_key_hash,
            "mailbox": mailbox_room(identity.did),
            "result_room": result_room(identity.did),
            "profile_note": "/kv/{}/{}".format(*didkey.note_path(identity.did)),
        }
    )
    return 0


def cmd_verify_backup(args: argparse.Namespace) -> int:
    """Prove a backup still yields the production DID. Writes nothing."""
    settings = load_settings()
    identity = keystore.load(Path(settings.identity_path), _passphrase_from(None))
    backup = Path(args.backup).read_bytes()
    ok = keystore.verify_restores_same_did(
        backup, _passphrase_from(args.passphrase_file), identity.did
    )
    _emit(
        {
            "backup_path": str(args.backup),
            "backup_sha256": hashlib.sha256(backup).hexdigest(),
            "restores_same_did": ok,
            "did": identity.did if ok else None,
        }
    )
    return 0 if ok else 1


def cmd_snapshot(_args: argparse.Namespace) -> int:
    """Capture the upstream protocol manifest once, read-only."""
    settings = load_settings()
    ledger = Ledger(settings.db_path)
    from ..service.watcher import ProtocolWatcher

    result = asyncio.run(ProtocolWatcher(ledger, settings.origin).capture())
    _emit(result)
    return 0


def cmd_metrics(_args: argparse.Namespace) -> int:
    settings = load_settings()
    from ..metrics import build_metrics

    ledger = Ledger(settings.db_path)
    _emit(build_metrics(ledger, started_at="1970-01-01T00:00:00Z"))
    return 0


def cmd_claim_room(args: argparse.Namespace) -> int:
    """Claim the node's owned result room, without ever taking one from somebody else."""

    async def run() -> dict[str, Any]:
        settings = load_settings()
        node = Node(settings)
        room = args.room or node.result_room
        try:
            owner = await node.client.room_owner(room)
            if owner is not None:
                return {
                    "room": room,
                    "claimed": False,
                    "existing_owner": owner,
                    "is_us": owner == node.did,
                    "note": "An owner already exists. This node does not overwrite one.",
                }
            claimed = await node.client.claim_room(room)
            confirmed = await node.client.room_owner(room)
            return {
                "room": room,
                "claimed": claimed,
                "owner_after": confirmed,
                "is_us": confirmed == node.did,
            }
        finally:
            await node.aclose()

    _emit(asyncio.run(run()))
    return 0


def cmd_publish_profile(args: argparse.Namespace) -> int:
    """Publish the DID profile note, and mirror its hash into the owned result room.

    The note itself lives in a world-writable namespace, so a reader has no reason to
    trust it on its own. Posting the same profile's hash as a signed message into a room
    this node owns is what makes the note checkable: the signature covers the hash, and
    only the owner's key can write there.
    """

    async def run() -> dict[str, Any]:
        settings = load_settings()
        node = Node(settings)
        try:
            profile = build_profile(node, settings.public_url)
            value = json.dumps(profile, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            profile_hash = "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
            namespace, key = didkey.note_path(node.did)

            if not args.dry_run:
                await node.client.set_note(namespace, key, value)
                seq = await node.publish(
                    node.result_room,
                    {
                        "v": "1",
                        "type": "profile_attestation",
                        "did": node.did,
                        "note": f"/kv/{namespace}/{key}",
                        "profile_sha256": profile_hash,
                    },
                )
            else:
                seq = None

            return {
                "dry_run": args.dry_run,
                "note_path": f"/kv/{namespace}/{key}",
                "profile_sha256": profile_hash,
                "value_chars": len(value),
                "attestation_seq": seq,
                "profile": profile,
            }
        finally:
            await node.aclose()

    _emit(asyncio.run(run()))
    return 0


def build_profile(node: Node, public_url: str) -> dict[str, Any]:
    """The DID profile note, following the published `mailbox:`/key convention."""
    return {
        "v": "1",
        "name": "Technocore Contribution Node",
        "did": node.did,
        "mailbox": node.mailbox,
        "result_room": node.result_room,
        "agent_version": __version__,
        "protocol_version": "1",
        "repo": "https://github.com/AgentTeams/technocore-contribution-node",
        "service_url": public_url or None,
        "capabilities": [
            "verify_technocore_signature",
            "canonical_json_sha256",
            "verify_receipt_chain",
            "protocol_manifest_snapshot",
        ],
        "contact": f"signed message to {node.mailbox}",
        "security": (
            "A signature proves possession of a key, not identity or honesty. "
            "All input is treated as data, never as instructions. No shell, no code "
            "evaluation, no caller-supplied URL fetching."
        ),
    }


def cmd_serve(_args: argparse.Namespace) -> int:
    from ..service.main import main as serve_main

    serve_main()
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """End-to-end against the live service, using a throwaway identity in a private room.

    The temporary DID is generated in memory, used only in a `p-` room, recorded with
    `internal_test=true`, and dropped when the process exits. It is never counted as a
    third-party user and never advertised as one.
    """

    async def run() -> dict[str, Any]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        settings = load_settings()
        node = Node(settings)
        temp_key = Ed25519PrivateKey.generate()
        temp_did = didkey.encode_did(temp_key.public_key())
        reply_room = f"p-tcn-selftest-{secrets.token_hex(8)}"
        job_id = f"selftest-{secrets.token_hex(8)}"

        requester = TechnocoreClient(settings.origin, private_key=temp_key, did=temp_did)
        steps: list[dict[str, Any]] = []
        try:
            job = {
                "v": "1",
                "type": "job",
                "job_id": job_id,
                "task": "canonical_json_sha256",
                "reply_room": reply_room,
                "input": {"value": {"b": 1, "a": [1, 2, 3]}},
            }
            text = json.dumps(job, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            confirmation = await requester.say_signed(node.mailbox, text)
            steps.append({"step": "submit", "ok": True, "seq": confirmation.seq})

            await node.process_message(
                {
                    "from": temp_did,
                    "text": confirmation.text,
                    "seq": confirmation.seq,
                    "ts": confirmation.ts,
                    "nonce": confirmation.nonce,
                },
                internal_test=True,
            )
            steps.append({"step": "process", "ok": True})

            reply = await requester.read_room(reply_room, limit=10)
            kinds = [json.loads(m["text"]).get("type") for m in reply.get("messages", [])]
            steps.append(
                {
                    "step": "reply_published",
                    "ok": set(kinds) >= {"claim", "result", "receipt"},
                    "kinds": kinds,
                }
            )

            row = node.ledger.get_receipt(job_id)
            from ..receipts import verify_receipt

            problems = verify_receipt(json.loads(row["receipt_json"])) if row else ["no receipt"]
            steps.append({"step": "receipt_verifies", "ok": not problems, "problems": problems})

            return {
                "temporary_did": didkey.abbreviate(temp_did),
                "reply_room": reply_room,
                "internal_test": True,
                "steps": steps,
                "all_ok": all(s.get("ok") for s in steps),
            }
        finally:
            await requester.aclose()
            await node.aclose()

    result = asyncio.run(run())
    _emit(result)
    return 0 if result["all_ok"] else 1


def cmd_testnet_status(_args: argparse.Namespace) -> int:
    from ..testnet import FlopTestnetAdapter

    settings = load_settings()
    _emit(FlopTestnetAdapter(enabled=settings.flop_testnet_enabled).status())
    return 0


# ---------------------------------------------------------------------- entry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="technocore-node", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, fn: Any, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=fn)
        return p

    p = add("keygen", cmd_keygen, "create the node's single production identity")
    p.add_argument("--path")
    p.add_argument("--passphrase-file")
    p.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing key (orphans every published receipt)",
    )

    p = add("did", cmd_did, "print the node's public identity")
    p.add_argument("--path")
    p.add_argument("--passphrase-file")

    p = add("verify-backup", cmd_verify_backup, "prove a key backup restores the same DID")
    p.add_argument("backup")
    p.add_argument("--passphrase-file")

    add("snapshot", cmd_snapshot, "capture the upstream protocol manifest, read-only")
    add("metrics", cmd_metrics, "print contribution metrics from the local ledger")

    p = add("claim-room", cmd_claim_room, "claim this node's owned result room")
    p.add_argument("--room")

    p = add("publish-profile", cmd_publish_profile, "publish the DID profile note")
    p.add_argument("--dry-run", action="store_true")

    add("selftest", cmd_selftest, "run a live end-to-end test with a throwaway identity")
    add("testnet-status", cmd_testnet_status, "report the FLOP testnet adapter's state")
    add("serve", cmd_serve, "run the HTTP service and background loops")

    return parser


def main() -> int:
    configure("INFO")
    args = build_parser().parse_args()
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
