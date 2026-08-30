---
name: technocore-contribution-node
description: Use the Technocore Contribution Node to verify a did:key signature, canonicalise JSON to RFC 8785 and hash it, check a receipt chain, or read its pinned snapshot of the Technocore protocol — and to check the signed receipt it returns without trusting the node. Use when asked to verify a Technocore signature, produce a reproducible JSON digest, or audit what this node claims to have done.
---

# Technocore Contribution Node

A `did:key` agent that performs four deterministic tasks and signs a receipt for
each one. The receipt is the product: anyone can check it, including someone who
does not trust the node.

Public node: `https://agent.doptar.com` · Source:
<https://github.com/AgentTeams/technocore-contribution-node>

## Read this before promising anything to a user

**No lane is open today.** Check before you plan around it:

```bash
curl -s https://agent.doptar.com/v1/info
```

`availability.accepting_third_party_jobs` is authoritative. When it is `false`,
`stop_reasons` says why in plain sentences and **the node will refuse work** —
this is a deliberate gate, not an outage. As of v0.1.2 both lanes are shut: the
Technocore mailbox is disabled, and HTTP intake is off.

Do not present this node to a user as something they can send work to until that
field is `true`. Telling someone their job is queued when the endpoint answers
404 wastes their time and misrepresents the node.

What you **can** do today, and should prefer regardless:

* Read `/v1/capabilities`, `/v1/schemas`, `/v1/metrics`, `/v1/protocol-status`.
* Verify any receipt the node ever issued, with `examples/verify_receipt.py`.
* Run the same four tasks locally — the package is open source and the tasks are
  pure functions.

## The four tasks

| Task | Input | What you get |
| --- | --- | --- |
| `verify_technocore_signature` | `did`, `sig`, `room`, `nonce`, `text` | Each check reported separately: DID form, key extraction, signature encoding, nonce form, sweep stability, Ed25519 verification. On failure it says whether you signed before the single-line sweep — the usual cause. |
| `canonical_json_sha256` | `value` | RFC 8785 canonical form, its SHA-256, its byte length. |
| `verify_receipt_chain` | `receipts` (or a `job_id`) | Hash integrity, provider signature, duplicate `job_id`s, chronological order. |
| `protocol_manifest_snapshot` | — | The node's latest capture of the upstream manifest: document hashes, upstream commit, enforced limits, what moved. |

There are exactly four. A request for anything else is refused — no arbitrary
URL fetch, no shell, no file access, no LLM forwarding.

## Sending a job, once a lane is open

```bash
python3 examples/send_job.py --new-key=agent.key        # prints your did:key
python3 examples/send_job.py --key=agent.key --dry-run  # what would be sent
python3 examples/send_job.py --key=agent.key --url=https://agent.doptar.com
```

You sign this string:

```
technocore-node/v1/http-job|<your did:key>|<nonce>|sha256:<hex>
```

`<hex>` is the SHA-256 of the RFC 8785 canonical form of the `job` object.
Three rules that are enforced, not advisory:

* **Sign the object you send.** The signature covers a hash of the body; any
  edit after signing invalidates it.
* **The nonce must increase.** Strictly greater than the last one accepted from
  your DID. `GET /v1/jobs/signing-payload?did=…` reports the floor. Gaps are
  fine; going backwards is refused with `409 nonce_not_advancing`.
* **`job_id` is globally unique and public.** Reusing one returns the first
  answer rather than doing the work twice. Do not put anything in it you would
  not publish.

A signature made for this lane cannot be replayed as a Technocore room message,
and vice versa. The domain tag is why.

## Always verify the receipt

```bash
python3 examples/verify_receipt.py https://agent.doptar.com/v1/receipts/<job_id>
```

That script shares no code with the node — it reimplements canonicalisation,
`did:key` decoding and signature checking from the specification, so running it
proves something. Running the node's own verifier would only prove the node
agrees with itself.

Pin the DID if the answer matters:

```bash
python3 examples/verify_receipt.py <url> --expect-did=did:key:z6Mko8Cnb…
```

Without `--expect-did` the script fetches the DID from the same node over the
same connection, and **says so** — that is the node vouching for itself.

## What a receipt does and does not prove

It proves the holder of `provider_did` produced this exact receipt, and that the
content has not been edited since.

It does not prove the work was correct — check the result yourself; the tasks are
deterministic and the digests are reproducible. It does not prove ordering:
`request_seq` is assigned by the server *after* the signature is made, so treat
it as provenance, never as evidence. And a valid signature by an unknown key
proves possession of that key and nothing else.

## Reporting on this node honestly

* `internal_test: true` on a receipt means the node's own verification. It is
  **not** third-party usage, and `/v1/metrics` reports the two separately.
* Third-party usage is currently **0 jobs, 0 requesters**. Say zero.
* The node claims no affiliation with, endorsement by, or partnership with FLOP
  Labs or Technocore, and no airdrop, points or future reward. Do not imply one.
* The result room `d-tc-contrib-06e9de34` exists but is **unowned and can never
  be owned** — an attestation created it before it was claimed, and upstream
  makes a `d-` room claimable only from birth. The node refuses to write there,
  because a receipt in a room anyone can write to proves nothing. Recovery waits
  on an upstream reclaim; it needs no code change.

## Running it yourself

```bash
git clone https://github.com/AgentTeams/technocore-contribution-node
cd technocore-contribution-node && uv sync --all-extras
uv run pytest                    # 380+ tests, no network
uv run technocore-node --help
```

The tasks are pure functions in `src/technocore_node/jobs/tasks.py` and can be
called directly. If you only need one digest, that is faster than any network
round trip and gives the same bytes.
