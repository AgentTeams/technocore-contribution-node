# Pre-release review — v0.2.0

Six rounds of adversarial review of the signed HTTP job intake lane, before the pull
request. Fourteen findings, all fixed. The reviewer blocked the merge three times and
lifted the block in round 6.

## What this was, and what it was not

It was a local [Codex CLI](https://github.com/openai/codex) session (`codex-cli 0.142.5`),
run with `--sandbox read-only` against the branch diff and the working tree, by the same
person who wrote the code. Each round was given the previous round's findings and asked
first to **verify the fixes actually held**, then to look for defects the fixes had
introduced.

It was **not** a GitHub Pull Request Review, not an independent audit, and not a
substitute for one. Nobody outside this project has read this code. The raw logs are kept
privately rather than published; this file is the summary, and it names what was found
rather than only that something was.

The reason for six rounds is visible in the findings below: three of the fourteen were
introduced by the fix for an earlier one. A single round would have shipped the first
version of each fix.

## Findings

Severity is the reviewer's: **P0** — work executed or a write attempted while the gate is
closed, a signature valid in the wrong domain, replay or nonce bypass, request data
reaching a shell or the network, cross-requester exposure, or a test that can write to a
live service. **P1** — a correctness bug, a documented claim the code does not keep, an
idempotency, durability or rate-limit hole. **P2** — clarity, naming, dead code.

### Round 1 — six findings

| | Finding | Fix |
| --- | --- | --- |
| **P0** | `tests/e2e` makes real writes and is exempt from the network guard because talking to a server is its purpose. Its docstring asked for a local instance; nothing enforced it. A typo in `TCN_E2E_ORIGIN` would have put those writes on the public instance under the production identity. | A non-loopback origin now aborts collection. It raises rather than skips: a silent skip on a misconfigured run looks exactly like a passing one. |
| **P1** | The HTTP lane parsed JSON with `json.loads`, which keeps the last of a duplicate key. `{"task":"a","task":"b"}` would be hashed as though only `b` were written, while a verifier keeping the first reads the same signed bytes differently — the signature verifies and the two parties disagree about what was signed. The mailbox lane already refused this. | Both lanes use `parse_strict`, which refuses it at the parse — the only place it can be seen. |
| **P1** | A job the schema refused still spent a nonce, contradicting the changelog and the code comment beside it. A caller could not resend a corrected request. | Validation is pure, so it runs before the claim. Execution still happens strictly after an atomic claim, so a replay re-validates cheaply and then loses. |
| **P1** | Four hand-built `Settings` in the live suite were missing the new field and would have failed with a `TypeError`, taking the owned-room and audit-copy live checks with them. | Updated. Not caught locally because that suite needs a server. |
| **P2** | The domain-separation comment credited a colon; the separator a room name cannot contain is `/`. The test had it right and the prose did not. | Corrected, and the test now asserts against the upstream's own name rule rather than an example. |
| **P2** | `MAX_SKEW_SECONDS` was defined, never used, and had no timestamp to apply to — a constant implying a time-bounded replay defence that does not exist. | Removed. |

### Round 2 — two findings

| | Finding | Fix |
| --- | --- | --- |
| **P1** | HTTP intake was gated on `TCN_MAILBOX_ENABLED`, so the HTTP-only configuration this release exists to offer could not run: it answered "mailbox intake is disabled" to a signed HTTP submission. | Safety is shared between lanes; enablement is not. Each lane has its own switch over the same conditions, and every gate site names the lane it is gating. |
| **P1** | A completed job and its receipt were two writes with a return through the caller in between. A crash there left a job marked complete — so the duplicate check refused every retry — whose receipt did not exist. | One transaction, performed inside the runner so both lanes get it and a third cannot forget to. |

### Round 3 — three findings, merge blocked

| | Finding | Fix |
| --- | --- | --- |
| **P1** | The round-2 fix was not enough. The job row is inserted *before* the work runs, so a failure writing the answer rolled back the completion and left the row — and a duplicate check keyed on the row's existence refused every retry. The round-2 test asserted the completion had rolled back, which was true and was not the property that mattered. | "Already seen" is not "already answered". A row without a receipt resumes; an answered one returns its first answer. Concurrent submissions of one `job_id` serialise. |
| **P1** | Nineteen digits satisfied the nonce pattern, and `2**63` does not fit a signed 64-bit column, so a well-signed request reached the bind and became a 500 — recording neither a rejection nor a nonce, and escaping the accounting every other malformed input is subject to. | Bounded where the value is already being checked. |
| **P1** | The published OpenAPI description said the API was read-only. It is, except for the one write route this release adds. | Corrected. An auditor reading that document was told the write surface did not exist. |

### Round 4 — two findings, merge blocked

| | Finding | Fix |
| --- | --- | --- |
| **P1** | A resume was charged the rate limit. The counter reads job rows, and the row it reads *is* the job being recovered — so at a low limit, the one retry that exists to recover an answer the requester already paid for was the request the limit refused, until the window rolled over. | A resume creates no row and is not charged for one. Genuinely new work still is. |
| **P1** | A task runs in a worker thread that no cancellation can stop. A client that disconnected mid-job released the job's slot while its thread carried on, and a retry started a second one — breaking single execution and the concurrency ceiling in the one situation where the requester is least able to see it. | The slot holds the running task; a second submission awaits it through a shield. The disconnect abandons the waiting, never the work. |

### Round 5 — one P0 and one P1, merge blocked

| | Finding | Fix |
| --- | --- | --- |
| **P0** | The round-4 fix introduced it. Joining was keyed on `job_id` alone — but `job_id` is public and globally unique by design, and the ownership check lives inside the run, which a joining caller never enters. Anyone who guessed an id while it was in flight was handed the first requester's result, receipt, reply room and DID. The isolation existed a moment earlier and a moment later, and not in the window that mattered. | The requester is held beside the task. A different one gets the same `job_id_taken` refusal it would have received at any other time. |
| **P1** | The route applied the rate limit before looking for an existing answer, so a client retrying after a dropped response was told to slow down instead of being handed the receipt it had already earned — and a crashed job could not be resumed at all, because that check refused it before the runner's resume path was reachable. | Idempotency lookup, then resume detection, then the limit. An answer that already exists costs nothing to hand over again. |

### Round 6 — no findings

P0, P1 and P2 all clear. The reviewer verified the round-5 fixes, walked the new route
ordering to confirm nothing became reachable that previously was not, and stated it would
not block the merge.

## What the reviewer got wrong

One correction, recorded because a review summary that reports only the reviewer's hits
is not a record of the review. In round 5 the prompt asserted that `receipts.job_id` had
no unique constraint. The reviewer checked rather than accepting it, found
`idx_receipts_job`, and said so. The prompt was wrong; the schema was right.

## Regression tests

Every finding has a test. The two from round 4 and two of the three from round 5 were
confirmed to **fail with the fix reverted** — a regression test that passes either way
records an intention rather than a behaviour. The third covers the route's ordering,
which a one-line revert does not restore.

## What is still not covered

* No external party has reviewed this code.
* The live suite runs against a local instance of the pinned upstream, not the public one.
  Behaviour that only appears at the real service's limits is untested by construction.
* This lane has never carried a third-party job, because it is disabled. Nothing here is
  evidence that it works in production, only that it does what its tests say.
