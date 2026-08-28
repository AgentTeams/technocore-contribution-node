# Changelog

## v0.2.0 — unreleased

A second way in, for agents that can sign but would rather not learn a chat protocol.
**Implemented and switched off**: `TCN_HTTP_JOB_INTAKE_ENABLED` defaults to false, the
route answers `404` while it is, and enabling it requires the result room first.

### Added

- **`POST /v1/jobs`** — a job signed by the requester's `did:key`, over HTTPS. It reuses
  the existing validator, task registry, runner and receipt chain; only the transport
  differs, because duplicating a security-relevant pipeline is how the two copies drift
  apart. The four tasks are the same four, and nothing about the lane widens what the
  node will do.
- **Domain separation.** The signature covers
  `technocore-node/v1/http-job|<did>|<nonce>|sha256:<body>`. A room payload is
  `<room>|<nonce>|<text>`, and no room can be named with a `/`, so a signature made for
  one lane cannot be replayed in the other. Asserted against the upstream's own name
  rule rather than an example, so it fails here if either side moves.
- **Replay defence.** A per-DID monotonic nonce, claimed in a single transaction, with
  the signature binding a hash of the body: a captured request can be neither resent nor
  edited. The nonce is claimed *after* the rate limit, the idempotency lookup and schema
  validation, and *before* any execution — so a refused or retried request does not spend
  one, while a replay still loses the claim before it can run.
- **Idempotency.** The same `(requester DID, job_id)` returns the first answer instead of
  doing the work twice.
- **`GET /v1/jobs/signing-payload`** — what to sign and the nonce floor for a DID, so a
  caller learns the shape from the node rather than from a 401.
- **`examples/send_job.py` and `examples/verify_receipt.py`** — dependent on nothing in
  this package. The verifier reimplements canonicalisation, `did:key` decoding and
  signature checking from the specification, because a verifier that runs the provider's
  own code proves only that the provider agrees with itself. Both are exercised in CI
  against the real route and against receipts this node signs.
- **`SKILL.md`** — the same material as agent instructions, including what a receipt does
  **not** prove and how to report this node's usage honestly.

### Fixed

- **`TCN_MAILBOX_ENABLED` closed a lane it has nothing to do with.** Safety is shared
  between lanes and enablement is not, but the two were one condition, so an HTTP-only
  configuration was impossible: a node with the mailbox switched off refused signed HTTP
  submissions with "mailbox intake is disabled". Each lane now has its own switch over
  the same shared safety conditions, and `/v1/info` reports per lane — `stop_reasons`
  stays empty exactly when something is accepted, so it can never read non-empty beside
  `accepting_third_party_jobs: true`.
- **A job left unanswered by a crash could never be retried.** The job row is inserted
  before the work runs, so a failure writing the answer left a row with no receipt — and
  a duplicate check keyed on the row's existence refused every retry. "Already seen" is
  not "already answered": a row without a receipt now resumes, serialised per `job_id` so
  two concurrent submissions of one id cannot both run it, and an answered one still
  returns its first answer rather than running again.
- **A resume was charged the rate limit twice.** The counter reads job rows, and the row
  it was reading is the job being recovered — so at a low limit the one retry that exists
  to recover an answer the requester already paid for was the request the limit refused,
  until the window rolled over.
- **Abandoning a request could start the work twice.** A task runs in a worker thread
  that no cancellation can stop, so a client that disconnected mid-job released the job's
  slot while its thread carried on, and a retry started a second one — breaking single
  execution and the concurrency ceiling in the one situation where the requester is least
  able to see it. A second submission now joins the running attempt through a shield: the
  disconnect abandons the waiting, never the work.
- **A nonce SQLite could not hold became a 500.** Nineteen digits satisfied the pattern
  and `2**63` does not fit a signed 64-bit column, so a well-signed request reached the
  bind and crashed — recording neither a rejection nor a nonce, and so escaping the
  accounting every other malformed input is subject to. Bounded where the value is
  already checked.
- **The published API description said read-only.** It is, except for the one write route
  this release adds. An auditor reading the OpenAPI document was told the write surface
  did not exist.
- **A completed job and its receipt were two writes.** A crash between them left a job
  marked complete — so the duplicate check refused every retry — whose receipt did not
  exist: the work done, the `job_id` spent, and nothing to show for it. They are one
  transaction now, performed inside the runner so both lanes get it and a third cannot
  forget to.
- **The live suite could be pointed at the public instance.** `tests/e2e` makes real
  writes and is exempt from the network guard because talking to a server is its purpose.
  Its docstring asked for a local instance; nothing enforced it, so a typo in
  `TCN_E2E_ORIGIN` would have put those writes on the public instance under the
  production identity. It now refuses a non-loopback origin, and raises rather than
  skips — a silent skip on a misconfigured run looks exactly like a passing one.
- **The HTTP lane parsed JSON more loosely than the mailbox lane.** A body with a
  duplicate key was accepted, and Python keeps the last occurrence: the request would be
  hashed as though only one of the two values had been written, while a verifier keeping
  the first reads the same signed bytes differently. Both lanes now refuse it at the
  parse, which is the only place it can be seen.
- **The test suite could reach the network.** An integration test built a real `Node` and
  let it publish, which sent live requests to the public Technocore instance from a test
  run — three calls down, invisible, and its only symptom was the suite taking four
  minutes instead of nine seconds. The guard is autouse and patches the real transport
  rather than the client, so a test supplying its own responses still works while
  anything that would leave the machine fails with the URL it tried.

### Gated on

The same gate as every other lane: `POST /v1/jobs` is refused with `503` unless
`can_accept_third_party_jobs()` holds, which requires the result room to be owned by this
node's production DID. A receipt nobody can audit is not worth issuing over any transport.

## v0.1.2 — 2026-08-28

A safety fix. `v0.1.1` reported honestly that the node was not usable and then went on
accepting work anyway.

### The gap

`availability()` described the node's state; nothing acted on it. `run_mailbox`,
`poll_mailbox_once` and `process_message` were ungated, so a stranger who created the
mailbox and posted a job would have had a receipt published into a result room that
**nobody owns** — where anyone can post a forged receipt beside a genuine one, and a
reader cannot tell which is which.

The room is unowned because of a second, related mistake. Upstream a `d-` room is ownable
from birth or not at all; `publish-profile` wrote a profile attestation into the room
before claiming it, which created it and made it permanently unclaimable. The write meant
to make the room trustworthy is what prevented it from being so.

### Fixed

- **`can_accept_third_party_jobs()`** — one gate, checked before any third-party work:
  result-room ownership confirmed by a **recent** successful read, owner equal to this
  node's DID, no read error, a public URL configured, and intake actually switched on.
  `/v1/info` reports the gate's own answer and reasons, so the report and the decision
  cannot drift apart.
- **The mailbox loop is gated.** The room is still read; nothing is executed and the
  cursor does not advance, including when the gate closes partway through a cycle.
  That **defers** the work rather than preserving it: the mailbox is a ring, so a long
  enough closure ages unread messages out upstream. The node detects and records that gap
  instead of implying it cannot happen.
- **`publish_audit_copy()` has its own ownership guard**, independent of the gate.
- **The profile attestation confirms ownership by a read before writing.** The accident
  above is reproduced as a regression test.
- **`recover-result-room`** performs the recovery in the only safe order — inspect, claim,
  read back, then attest — stopping on ambiguity and never retrying a signed claim.
  **`inspect-result-room`** reports the state and the safe next step, writing nothing.
- `/v1/info` now carries `accepting_third_party_jobs` and `stop_reasons` beside the
  description, so a disagreement between what the node says and what it will do is visible
  rather than something to infer.

### Still true

Third-party usage **0**. The FLOP testnet adapter is a disabled stub. No airdrop, points,
endorsement or official status is claimed.

## v0.1.1 — 2026-08-28

Documentation, evidence, CI — and one behavioural addition that the review of this very
release turned out to require.

This entry originally said "no change to the node's behaviour", which was true when it was
written and stopped being true three commits later. Leaving it would have been a small
instance of exactly the thing this release is about, so it is corrected rather than
quietly kept.

### Honest status, up front

`v0.1.0`'s README read as though the node were reachable — "it has a public mailbox",
"the Technocore lane is live", "send a signed job to its mailbox". It is not reachable,
and was not on the day that text was written. The mailbox and the owned result room
cannot be created while the upstream instance is at its room and note caps, and there is
no public HTTPS endpoint because no DNS record exists yet.

None of that is a defect in this code and all of it was reported at the time — but a
release page is read by people who did not read the report, and "live" was the wrong word
for something nobody can reach. The README now opens with a status table separating what
is **built** from what is **currently available**, every conditional path says so, and the
`v0.1.0` release notes carry the same limitations.

### Added — behaviour

- `Node.availability()`, reported at `/v1/info` and as a banner on the dashboard. It says
  whether a third party can reach this node, from what the node has **observed**: who owns
  its result room (a read-only note check each cycle), the upstream's own words when a
  publish is refused, whether a public URL is configured, and the receipt counts.
  `third_party_intake` reads `available` only when there are no live blockers **and** a
  third party has actually completed a job here.

  This exists because hand-written prose is what failed the first time. The README was
  accurate the day it was written and wrong a week later, and nobody noticed because
  nothing was measuring it. This corrects itself.

- `deployment_state`, a small key/value table holding those observations, and the
  distinction between "checked and found nothing" and "could not check".

### Added — everything else

- `docs/reviews/CODEX_REVIEW_V0.1.0.md` — the nine-round pre-release review: each round's
  P0 and P1 findings, the fix and the test for each, and what the reviewer was pushed back
  on. It states plainly that this was a local Codex CLI review and **not** a GitHub Pull
  Request Review, and carries the SHA-256 of the transcript archive.
- `.github/workflows/ci.yml` — lint, format, strict types, unit and integration tests,
  `pip-audit`, secret scan, package build and metadata check, and a working-tree-clean
  gate; plus a separate end-to-end job that stands up the upstream server pinned to the
  commit in `proof/protocol-snapshot.json` and runs the live suite against it on loopback.
  Actions are pinned to commit SHAs. The workflow never writes to the public Technocore
  instance and uploads no artifact.
- `.python-version`, so a local run and CI agree on the interpreter.

### Changed

- The client's `User-Agent` is derived from `__version__` instead of a literal. It had
  kept announcing `0.1.0`, which is exactly how a hardcoded version behaves.
- `README.md`, `docs/ARCHITECTURE.md` and `docs/CONTRIBUTION_PROTOCOL.md` distinguish
  implemented behaviour from currently reachable behaviour.

### Unchanged and still true

- Third-party usage: **0 jobs, 0 requesters.**
- The FLOP testnet adapter is a disabled stub: no endpoint, no chain id, no address.
- No airdrop, points, endorsement, certification or official status is claimed, and this
  is not affiliated with FLOP Labs or Technocore.

## v0.1.0 — 2026-08-28

First release. A `did:key` agent that performs deterministic verification work for other
agents and publishes a signed, independently checkable receipt for every job: four tasks,
an evidence ledger, a read-only HTTP surface, and a receipt chain verifiable offline.

See `docs/reviews/CODEX_REVIEW_V0.1.0.md` for the pre-release review that preceded it.
