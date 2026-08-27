"""Wire schema for the contribution job protocol.

Every message on this protocol is one line of compact JSON, because the transport stores
one line per record and sweeps anything that would break that. The schemas below are
strict on purpose — `additionalProperties: false` everywhere, bounded strings, an
enumerated task list — since every request arrives from a stranger and the validator is
the first thing that sees it.

The signature the *transport* checks proves the sender holds a key. It says nothing about
whether the contents are well-formed, in range, or meant well; that is this module's job.
"""

from __future__ import annotations

from typing import Any, Final

from ..crypto.didkey import DID_PATTERN, SIG_PATTERN

PROTOCOL_VERSION: Final = "1"

#: Room names the transport will accept, so a `reply_room` cannot smuggle a path.
NAME_PATTERN: Final = r"^[a-z0-9][a-z0-9_-]{0,47}$"
JOB_ID_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$"
HASH_PATTERN: Final = r"^sha256:[0-9a-f]{64}$"
TIMESTAMP_PATTERN: Final = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"

TASKS: Final = (
    "verify_technocore_signature",
    "canonical_json_sha256",
    "verify_receipt_chain",
    "protocol_manifest_snapshot",
)

#: The upstream cap is 4096 characters for a whole message, and a job has to leave room
#: for the reply. Inputs are held well under it so a result always fits in one message.
MAX_INPUT_CHARS: Final = 2400

JOB_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Contribution job request",
    "type": "object",
    "additionalProperties": False,
    "required": ["v", "type", "job_id", "task", "reply_room"],
    "properties": {
        "v": {"const": PROTOCOL_VERSION},
        "type": {"const": "job"},
        "job_id": {
            "type": "string",
            "pattern": JOB_ID_PATTERN,
            "description": "Caller-chosen and GLOBALLY unique — it is also the public "
            "receipt identifier, so include a random component. A repeat from the same "
            "requester is answered from the ledger; one from a different requester is "
            "refused with job_id_taken.",
        },
        "task": {"enum": list(TASKS)},
        "reply_room": {
            "type": "string",
            "pattern": NAME_PATTERN,
            "description": "Where the claim, result and receipt are posted. Must be an "
            "unlisted room — p-<random> or mb-p-<random> — because the name is the only "
            "evidence you hold it. A plain mb- room is refused: it proves its writers "
            "are signed, not that it is yours.",
        },
        "input": {"type": "object"},
        "created_at": {"type": "string", "pattern": TIMESTAMP_PATTERN},
    },
}

CLAIM_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Contribution job claim",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "v",
        "type",
        "job_id",
        "provider_did",
        "request_hash",
        "accepted_at",
        "max_processing_ms",
    ],
    "properties": {
        "v": {"const": PROTOCOL_VERSION},
        "type": {"const": "claim"},
        "job_id": {"type": "string", "pattern": JOB_ID_PATTERN},
        "provider_did": {"type": "string", "pattern": f"^{DID_PATTERN}$"},
        "request_hash": {"type": "string", "pattern": HASH_PATTERN},
        "accepted_at": {"type": "string", "pattern": TIMESTAMP_PATTERN},
        "max_processing_ms": {
            "type": "integer",
            "minimum": 1,
            "description": "A fixed processing ceiling, not an estimate. Past it the job "
            "fails with task_timeout and a result still gets posted.",
        },
    },
}

RESULT_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Contribution job result",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "v",
        "type",
        "job_id",
        "task",
        "requester_did",
        "provider_did",
        "request_hash",
        "result_hash",
        "status",
        "completed_at",
        "impl_version",
        "sig",
    ],
    "properties": {
        "v": {"const": PROTOCOL_VERSION},
        "type": {"const": "result"},
        "job_id": {"type": "string", "pattern": JOB_ID_PATTERN},
        "task": {"enum": list(TASKS)},
        "requester_did": {"type": "string", "pattern": f"^{DID_PATTERN}$"},
        "provider_did": {"type": "string", "pattern": f"^{DID_PATTERN}$"},
        "request_hash": {"type": "string", "pattern": HASH_PATTERN},
        "result_hash": {"type": "string", "pattern": HASH_PATTERN},
        "status": {"enum": ["ok", "error"]},
        "summary": {"type": "object"},
        "error": {"type": "string", "maxLength": 200},
        "completed_at": {"type": "string", "pattern": TIMESTAMP_PATTERN},
        "impl_version": {"type": "string", "maxLength": 32},
        "source_commit": {"type": "string", "maxLength": 40},
        "sig": {
            "type": "string",
            "pattern": f"^{SIG_PATTERN}$",
            "description": "Detached Ed25519 signature over the RFC 8785 canonical form "
            "of this object with `sig` removed. Verifiable offline, "
            "independently of the transport's own signature.",
        },
    },
}

RECEIPT_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Contribution receipt",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "v",
        "type",
        "receipt_id",
        "job_id",
        "requester_did",
        "provider_did",
        "request_hash",
        "result_hash",
        "internal_test",
        "created_at",
        "receipt_hash",
        "sig",
    ],
    "properties": {
        "v": {"const": PROTOCOL_VERSION},
        "type": {"const": "receipt"},
        "receipt_id": {"type": "string", "pattern": JOB_ID_PATTERN},
        "job_id": {"type": "string", "pattern": JOB_ID_PATTERN},
        "requester_did": {"type": "string", "pattern": f"^{DID_PATTERN}$"},
        "provider_did": {"type": "string", "pattern": f"^{DID_PATTERN}$"},
        "request_room": {"type": "string", "pattern": NAME_PATTERN},
        "reply_room": {"type": "string", "pattern": NAME_PATTERN},
        "request_seq": {
            "type": ["integer", "null"],
            "description": "Server-assigned, and therefore NOT covered by any signature "
            "made before the write. Provenance, not proof. There is no result_seq: the "
            "receipt is signed before the result is published, so that number does not "
            "exist yet and adding it later would invalidate the signature.",
        },
        "request_hash": {"type": "string", "pattern": HASH_PATTERN},
        "result_hash": {"type": "string", "pattern": HASH_PATTERN},
        "provider_signature": {
            "type": "string",
            "pattern": f"^{SIG_PATTERN}$",
            "description": "The result's own detached signature, carried so a receipt "
            "can be checked without re-fetching the result message.",
        },
        "internal_test": {
            "type": "boolean",
            "description": "True for this node's own end-to-end tests. Such jobs are "
            "excluded from every third-party usage figure it publishes.",
        },
        "created_at": {"type": "string", "pattern": TIMESTAMP_PATTERN},
        "receipt_hash": {"type": "string", "pattern": HASH_PATTERN},
        "sig": {"type": "string", "pattern": f"^{SIG_PATTERN}$"},
        # Reserved for a settlement network. Declared rather than merely described,
        # because `additionalProperties: false` means an undeclared field is refused —
        # a reservation the schema rejects is not a reservation, and the adapter that
        # was written against the documented one produced receipts invalid under it.
        #
        # Each is populated only from a value a network actually returned. An adapter
        # that cannot observe a field leaves it absent: a receipt carrying an invented
        # block height is a forged receipt, however well meant. See
        # docs/TESTNET_ADAPTER.md.
        "network": {"type": "string", "maxLength": 48},
        "tx_hash": {"type": "string", "maxLength": 128},
        "block_number": {"type": "integer", "minimum": 0},
        "testnet_job_id": {"type": "string", "maxLength": 128},
        "compute_units": {"type": "number", "minimum": 0},
        "verifier_did": {"type": "string", "pattern": f"^{DID_PATTERN}$"},
    },
}

#: The optional settlement fields, named once so schema, adapters and docs agree.
RESERVED_NETWORK_FIELDS: Final = (
    "network",
    "tx_hash",
    "block_number",
    "testnet_job_id",
    "compute_units",
    "verifier_did",
)

#: Per-task input schemas. Absent from this map means the task takes no input at all.
TASK_INPUT_SCHEMAS: Final[dict[str, dict[str, Any]]] = {
    "verify_technocore_signature": {
        "type": "object",
        "additionalProperties": False,
        "required": ["room", "nonce", "text", "did", "sig"],
        "properties": {
            "room": {"type": "string", "maxLength": 64},
            "nonce": {"type": ["string", "integer"]},
            "text": {"type": "string", "maxLength": 1600},
            "did": {"type": "string", "maxLength": 80},
            "sig": {"type": "string", "maxLength": 120},
        },
    },
    "canonical_json_sha256": {
        "type": "object",
        "additionalProperties": False,
        "minProperties": 1,
        "maxProperties": 1,
        "properties": {
            "value": {"description": "Any JSON value, canonicalised as received."},
            "json_text": {
                "type": "string",
                "maxLength": 1600,
                "description": "JSON source text, parsed strictly first.",
            },
        },
    },
    "verify_receipt_chain": {
        "type": "object",
        "additionalProperties": False,
        "minProperties": 1,
        "maxProperties": 1,
        "properties": {
            "receipts": {
                "type": "array",
                "minItems": 1,
                "maxItems": 8,
                "items": {"type": "object"},
            },
            "job_id": {
                "type": "string",
                "pattern": JOB_ID_PATTERN,
                "description": "Verify a receipt this node holds in its own ledger. It "
                "checks the stored receipt's hashes and signature; it does not re-read "
                "the published copy, so it says the receipt is internally sound, not "
                "that it is currently visible in the owned room. Ask /v1/receipts/"
                "<job_id> for that.",
            },
        },
    },
    "protocol_manifest_snapshot": {
        "type": "object",
        "additionalProperties": False,
        "properties": {},
        "description": "Takes no input. The origin is compiled in; this task will not "
        "fetch a caller-supplied URL.",
    },
}
