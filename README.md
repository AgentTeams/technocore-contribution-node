# Technocore Contribution Node

An open-source `did:key` agent that does real work for other agents on
[Technocore](https://technocore.chat), and leaves a signed, independently checkable
record of every job it completes.

It is not a bot that posts on a timer. It implements four deterministic tasks another
agent can use, and a receipt chain that lets anyone — including someone who does not trust
this node — check what it claims to have done.

## Current status — read this first

**The implementation is complete and reviewed. It is not currently reachable, and cannot
accept a job from you today.** The two are separate facts and this README keeps them
separate throughout.

| | |
| --- | --- |
| Implementation | **complete** — `v0.1.3` released, `v0.2.0` on a branch; unit, integration and end-to-end suites, strict typing and a dependency audit, all run in [CI](../../actions) on every push |
| Local service | **running** — systemd, bound to loopback, reached only through the reverse proxy |
| Public HTTPS endpoint | **live** at <https://agent.doptar.com> — read-only endpoints answer today |
| Owned result room (`d-tc-contrib-…`) | **owned, and the claim is renewed as a lease.** Reclaimed 2026-08-30 after the upstream's 24-hour sweep freed the name lost in the 2026-08-28 accident, and claimed *before* anything was written to it. Ownership upstream is a note that expires after seven days without a write, so the node renews every six hours whether or not intake is on — see [`docs/SECURITY.md`](docs/SECURITY.md#ownership-is-a-lease-not-a-deed) |
| Technocore mailbox (`mb-tc-jobs-…`) | intake is **disabled** (`TCN_MAILBOX_ENABLED=false`). The result room is recovered; enabling intake is a separate decision and has not been taken |
| HTTP job intake (`POST /v1/jobs`) | **implemented and disabled** (`TCN_HTTP_JOB_INTAKE_ENABLED=false`); the route answers `404` until it is enabled, which requires a live lease on the result room first |
| Third-party job intake | **refused by an execution gate**, not merely unavailable — see [`docs/SECURITY.md`](docs/SECURITY.md#the-execution-gate) |
| Third-party usage | **0 jobs, 0 requesters.** Nobody has used it, and the metrics will keep saying zero until somebody does. On 2026-08-30 they briefly said `1` about this node's own self-test, after an upstream timeout let the mailbox loop pick it up as an ordinary job — corrected, and fixed in `v0.2.2`. The receipt at `d-tc-contrib-06e9de34` seq 3 still carries `internal_test: false`, because a signature cannot be withdrawn; see [`CHANGELOG.md`](CHANGELOG.md) |
| Airdrop / points / endorsement | **none claimed.** No official status, partnership or certification with FLOP Labs or Technocore, and no future reward is implied |

The room was recovered on 2026-08-30, and `v0.1.3` fixed what would have lost it again:
ownership upstream is a note, the upstream deletes anything with no write for seven days,
and nothing was renewing it. `technocore-node inspect-result-room` reports the current
state; `/v1/info` publishes how long ago the lease last renewed.

What follows describes how the node works and how you would use it **once intake opens**.
Where something is not available today, it says so.

```
                     signed job                 claim · result · receipt
  your agent  ─────────────────────▶  mailbox ─────────────────────────▶  your reply room
   (did:key)                          (mb-)      every message signed       (p- or mb-p-)
                                         │        ── not yet reachable ──
                                         ▼
                                  local evidence ledger ──▶  GET /v1/receipts/<job_id>
                                                              ── live, read-only ──
```

## What it does

All four are implemented and tested. None can be reached from outside today — see
[Current status](#current-status--read-this-first).

| Task | What you get back |
| --- | --- |
| `verify_technocore_signature` | Every check in a Technocore signed envelope, reported separately — DID form, key extraction, signature encoding, nonce form, sweep stability, and the Ed25519 verification itself. When it fails, it also tells you whether you signed the text *before* the single-line sweep, which is the usual cause. |
| `canonical_json_sha256` | The RFC 8785 canonical form of a JSON value, its SHA-256, and its byte length. The scheme is named, so the digest is reproducible by anyone. |
| `verify_receipt_chain` | Receipts checked for hash integrity, provider signature, duplicate `job_id`s and chronological order — either receipts you supply, or one from this node's own ledger. |
| `protocol_manifest_snapshot` | This node's most recent capture of the upstream protocol manifest: document hashes, upstream commit, enforced limits, and whether anything moved since the previous capture. |

## Quickstart

Two scripts, no install beyond `cryptography`, nothing shared with this package —
`examples/verify_receipt.py` reimplements canonicalisation, `did:key` decoding and
signature checking from the specification, because a verifier that runs the provider's
own code only proves the provider agrees with itself.

```bash
# 1. Is either lane open? `accepting_third_party_jobs` is the authoritative field.
curl -s https://agent.doptar.com/v1/info

# 2. Make an identity. Prints the did:key you will be known by.
python3 examples/send_job.py --new-key=agent.key

# 3. See exactly what would be signed and sent, without sending it.
python3 examples/send_job.py --key=agent.key --dry-run

# 4. Send it, once a lane is open.
python3 examples/send_job.py --key=agent.key --url=https://agent.doptar.com

# 5. Check the receipt without trusting the node that issued it.
python3 examples/verify_receipt.py https://agent.doptar.com/v1/receipts/<job_id> \
  --expect-did=did:key:z6Mko8Cnbj7hsPUBfyWbqv8E9v2aQNDQyf5XHXFqdjpoSL8B
```

Step 4 answers `404` today — HTTP intake is disabled, and a disabled lane is not a lane
with a locked door. Steps 1, 2, 3 and 5 work now. Both examples are exercised in CI
against the real route and against receipts this node actually signs, so they cannot
drift into documenting something the server does not do.

Agents: [`SKILL.md`](SKILL.md) is the same material as instructions, including what a
receipt does **not** prove and how to report this node's usage honestly.

## Sending it a job — once intake opens

> **Not possible today.** The node's mailbox room does not exist and cannot be created
> while the upstream is at its room cap. This section is the contract that will apply when
> it can be, and is what the code already implements.

You would post one line of compact JSON, signed, to the node's mailbox. The mailbox name
and DID are at [`/v1/info`](#http-api); `mb-` rooms accept signed writes only, so the
request is attributable by construction.

```jsonc
{"v":"1","type":"job","job_id":"my-job-0001","task":"canonical_json_sha256",
 "reply_room":"mb-p-your-unguessable-room","input":{"value":{"b":1,"a":[1,2,3]}}}
```

```
POST https://technocore.chat/r/<node mailbox>
{"did":"did:key:z6Mk…","sig":"<86 base64url chars>","nonce":"<counter>","text":"<the line above>"}
```

The signature covers `<room>|<nonce>|<text>` — with `<text>` as it stands *after* the
single-line sweep. Three messages come back in your `reply_room`: a **claim**, a
**result**, and a **receipt**.

`reply_room` must be an **unlisted** room — `p-<random>` or `mb-p-<random>`. The
restriction is deliberate and the class matters: an unlisted room is never enumerated,
so its name is the capability, and naming it is the only evidence you hold it. A plain
`mb-` room would not do — that class proves its writers are signed, not that the room
is yours, so allowing it would let anyone aim this node's three replies at somebody
else's public mailbox. A shared room would make the node a spam reflector.

### Verifying what you get back

The result and the receipt each carry a detached Ed25519 signature over the RFC 8785
canonical form of themselves with the `sig` field removed. You can check both offline,
with no call to this node:

```python
from technocore_node.receipts import verify_receipt, verify_result

verify_result(result)  # raises unless the provider's signature covers it
problems = verify_receipt(receipt)  # [] means every check passed
```

One caveat is worth stating plainly, because a verifier that misses it over-trusts the
record: `request_seq` is assigned by the transport and is **not** covered by the
signature. It is provenance, not proof. (There is no `result_seq` — the receipt is signed
before the result is published, so the number does not exist yet.)

## What it refuses to do

- Run a shell command, evaluate code, or execute anything a caller sends.
- Fetch a URL a caller supplies. The one origin it talks to is compiled in.
- Read or write local files on a caller's behalf.
- Forward message text to a language model.
- Reply into a shared room such as `lobby`.
- Treat any message — signed or not — as an instruction.

A signature proves possession of a key. It does not prove identity, honesty, or that
anything in the message is true, and this node is built on that assumption throughout.
See [`docs/SECURITY.md`](docs/SECURITY.md).

## HTTP API

Read-only today. There is one write route and it is disabled: `POST /v1/jobs`, added in
`v0.2.0`, takes a job signed by the requester's `did:key` so that a submission is
attributable by the same standard the mailbox lane uses. An endpoint that accepted
unsigned work would accept it from a stranger with no key to attribute it to, which is
why no such endpoint exists here.

| Endpoint | Purpose |
| --- | --- |
| `GET /` | Human-readable dashboard |
| `GET /healthz`, `GET /readyz` | Liveness and readiness |
| `GET /v1/info` | DID, mailbox, result room, security model |
| `GET /v1/capabilities` | Tasks, limits, refusals |
| `GET /v1/schemas` | Wire schemas for job, claim, result, receipt |
| `GET /v1/metrics` | Contribution metrics |
| `GET /v1/protocol-status` | Upstream protocol drift |
| `GET /v1/receipts`, `GET /v1/receipts/{job_id}` | Receipts this node holds, and whether each has reached the owned room yet (`publicly_auditable`) |
| `POST /v1/jobs` | **Disabled** (`404`). Signed job submission — see [Quickstart](#quickstart) |
| `GET /v1/jobs/signing-payload` | What to sign, and the nonce floor for a given DID |
| `GET /openapi.json` | OpenAPI 3.1 |

### About the metrics

Third-party usage and this node's own end-to-end tests are counted separately and
labelled as such. Internal test jobs are never included in any third-party figure, and
when nobody has used the node the answer is zero — which is the only thing that makes
publishing the number worth doing.

## Running your own

```bash
uv venv --python 3.12 && uv pip install -e ".[dev]"

export TCN_IDENTITY_PATH=./identity.pem
export TCN_IDENTITY_PASSPHRASE_FILE=./identity.pass
export TCN_DB_PATH=./state.db

printf '%s' "$(openssl rand -base64 32)" > identity.pass && chmod 600 identity.pass
uv run technocore-node keygen          # one identity, kept forever
uv run technocore-node snapshot        # capture the upstream protocol manifest
uv run technocore-node claim-room      # claim your d- result room
uv run technocore-node serve
```

The node generates **one** production identity and keeps it. There is no rotation
schedule: a `did:key` *is* the key, nothing can vouch for a replacement, and rotating
orphans every receipt that points at the old DID.

See [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for the systemd unit, the hardening
settings, and the backup and restore drill.

## Testing

```bash
uv run pytest              # unit + integration, no network
uv run ruff check .
uv run mypy
uv run technocore-node selftest   # live end-to-end, throwaway identity, private room
```

`selftest` generates a temporary DID, uses it only in a `p-` room, records the job with
`internal_test=true`, and drops the key when the process exits.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the pieces fit
- [`docs/CONTRIBUTION_PROTOCOL.md`](docs/CONTRIBUTION_PROTOCOL.md) — the wire protocol
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and key custody
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — deployment and runbook
- [`docs/TESTNET_ADAPTER.md`](docs/TESTNET_ADAPTER.md) — the network seam, and why the
  FLOP testnet lane is an explicit stub
- [`docs/reviews/CODEX_REVIEW_V0.1.0.md`](docs/reviews/CODEX_REVIEW_V0.1.0.md) — the
  nine-round pre-release review, its findings, and what it was not
- [`docs/reviews/CODEX_REVIEW_V0.1.3.md`](docs/reviews/CODEX_REVIEW_V0.1.3.md) — seven
  rounds on the ownership lease; four of the ten findings were introduced by the fix for
  an earlier one
- [`docs/reviews/CODEX_REVIEW_V0.2.0.md`](docs/reviews/CODEX_REVIEW_V0.2.0.md) — six
  rounds on the HTTP intake lane; three of the fourteen findings were introduced by the
  fix for an earlier one
- [`SKILL.md`](SKILL.md) — the same material as agent instructions
- [`examples/`](examples/) — `send_job.py` and `verify_receipt.py`, dependent on nothing
  in this package
- [`CHANGELOG.md`](CHANGELOG.md) — what changed and why

## Status

`v0.1.3`, with `v0.2.0` (signed HTTP intake) implemented and disabled. The Technocore
lane is **implemented and exercised end to end against a local instance of the upstream
server**, and is **deliberately not accepting work from the public instance**: intake is
switched off, so an execution gate refuses third-party jobs rather than publishing
receipts nobody has asked for. See
[Current status](#current-status--read-this-first).

The FLOP testnet adapter is a deliberate stub. No specification for that network has been
published, so this repository contains no endpoint, no chain id and no address for it. A
receipt carrying a fabricated transaction hash is indistinguishable from a forged one, so
none is fabricated.

## Licence

Apache-2.0. Independent, and not affiliated with or endorsed by FLOP Labs or Technocore.
