# Architecture

## The shape of it

> The two Technocore rooms below do not exist yet: the public instance is at its room cap.
> Everything inside the node is built and tested; the arrows crossing into Technocore are
> the part waiting on upstream capacity. See the README's status table.

```
                    Technocore (technocore.chat)
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
   mb-tc-jobs-<fp>      reply room           d-tc-contrib-<fp>
   (public mailbox)     (requester's)        (owned, this node writes)
        │                    ▲                    ▲
        │ signed job         │ claim/result/      │ profile attestation,
        ▼                    │ receipt            │ releases
  ┌──────────────────────────┴────────────────────┴──────────────────┐
  │  service/node.py — mailbox loop, publication, cursors            │
  │        │                                                          │
  │        ▼                                                          │
  │  jobs/runner.py — validate → claim → execute → result → receipt   │
  │        │                    │                                     │
  │        ▼                    ▼                                     │
  │  jobs/tasks.py         receipts/receipt.py                        │
  │  (4 pure functions)    (canonical hash + Ed25519)                 │
  │        │                    │                                     │
  │        └────────┬───────────┘                                     │
  │                 ▼                                                 │
  │        ledger/db.py — SQLite WAL evidence ledger                  │
  │                 │                                                 │
  │                 ▼                                                 │
  │        api/app.py — read-only HTTP, 127.0.0.1 only                │
  └───────────────────────────────────────────────────────────────────┘
```

## Why the pieces are split the way they are

**`jobs/runner.py` knows nothing about HTTP.** It takes text and a sender DID and returns
an `Outcome`. That is what makes the whole lifecycle testable without a network — and,
more importantly, it is what keeps a task from ever reaching one. If the runner cannot
publish, a task cannot make it publish.

**`protocol/` mirrors the upstream server rather than paraphrasing it.** `sweep.py` is a
line-for-line equivalent of the server's `clean_text`, and `crypto/didkey.py` matches its
`didkey.py` acceptance boundary. A signature is only worth something if both sides agree
on the exact bytes, so both files carry the upstream commit they were checked against.

**`ledger/` holds hashes, not payloads.** Technocore rooms are a ring and notes expire
after a week of silence, so the upstream cannot be the record. But the requests come from
strangers, so the record keeps what is needed to re-verify a chain and no more.

**`api/` is read-only.** Work arrives over the signed mailbox, where it is attributable.
An HTTP endpoint that accepted jobs would accept them from an unauthenticated stranger
with no key to attribute the work to.

## Where the trust boundaries are

| Boundary | What crosses it | What is assumed |
| --- | --- | --- |
| Technocore → mailbox loop | Signed messages from strangers | Only that the sender holds the key. Nothing about content, honesty, or intent. |
| Mailbox loop → runner | Raw text, sender DID | Nothing. The text is parsed and schema-validated before anything reads a field. |
| Runner → task | A validated input object | The schema held. Tasks are pure and cannot reach the network or the filesystem. |
| Node → Technocore | Signed claims, results, receipts | The `reply_room` is a stranger's string, so it must name an unlisted room — the one class whose name is evidence the requester holds it. |
| Anyone → HTTP API | A GET | Nothing. Read-only, and it returns no host detail. |

## The lifecycle

```
JOB ──▶ VALIDATED ──▶ CLAIM ──▶ EXECUTE ──▶ RESULT ──▶ RECEIPT ──▶ CONFIRMED
 │          │                       │           │          │
 │          │                       │           │          └─ published to reply_room,
 │          │                       │           │             stored in the ledger
 │          │                       │           └─ detached Ed25519 signature over the
 │          │                       │              RFC 8785 canonical form
 │          │                       └─ bounded: a fixed processing ceiling, then
 │          │                          task_timeout — still a signed answer
 │          └─ schema, task registry, reply-room class, input schema, rate limit
 └─ recorded before any work happens, so a crash leaves a known state
```

`job_id` is the idempotency key. The `INSERT` is the arbiter: whichever delivery wins the
insert does the work, and every other one stops.

## What a failure does

| Failure | Behaviour |
| --- | --- |
| Malformed message | Recorded as a rejection. Nothing is published — replying would let a stranger choose the room this node writes into. |
| Task raises | Becomes a signed `status: "error"` result. The requester is owed an answer either way. |
| Task exceeds its ceiling | `task_timeout`, signed result, job marked failed. |
| Upstream 429 | Retried twice on the server's own `Retry-After` (clamped), then surfaced. |
| Upstream 422 (duplicate) | Never retried — the upstream states plainly that the same bytes are refused again. |
| Write not readable back | `WriteUnconfirmed`. A 200 is not evidence the server stored our bytes. |
| Process dies mid-job | The cursor and the nonce high-water mark are on disk, and the receipt is written before either copy is announced. A restart does not re-run the job — the `job_id` check suppresses that deliberately — but the receipt still exists and any unannounced copy is still owed, so publication resumes even though execution does not. |
| Owned-room publish fails | The receipt stays `owed` and is retried a few at a time. After several failures it is quarantined so it cannot stall the queue, and surfaces in `/v1/metrics`. |
| Protocol document changes | Recorded and surfaced at `/v1/protocol-status`. No automatic code change, ever. |
