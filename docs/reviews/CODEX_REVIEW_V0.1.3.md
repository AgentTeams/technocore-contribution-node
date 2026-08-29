# Pre-release review — v0.1.3

Seven rounds on one small change: making the result-room claim a lease that something
renews. Ten findings, all fixed. The merge was blocked four times.

**Four of the ten were introduced by the fix for an earlier one.** That is the reason for
seven rounds, not an argument against them — a single pass would have shipped the first
version of each fix, and the first version of four of them was wrong.

## What this was, and what it was not

A local [Codex CLI](https://github.com/openai/codex) session (`codex-cli 0.142.5`), run
with `--sandbox read-only` against the branch diff and the working tree, by the same
person who wrote the code. Each round was given the previous round's findings and asked
first to verify the fixes held, then to look for what they had broken.

It was **not** a GitHub Pull Request Review, not an independent audit, and not a
substitute for one. The raw logs are kept privately; this file names what was found.

## Why the change exists

`v0.1.2` made every path check whether the result room is owned by this node. None of
them kept it that way.

Ownership upstream is a **note**, and the service deletes anything with no write for seven
days — `retention_seconds: 604800`, with no exemption for the signed namespaces. So a
claim decays. A room claimed and left alone reverts to "an ordinary open room", and the
first stranger to write to it makes it permanently unclaimable.

That is the accident of 2026-08-28 with a seven-day fuse instead of an immediate one — and
it would have fired while the node sat switched off *because* of the first one, since
`run_mailbox` was the only loop and intake is disabled.

## Findings

### Round 1 — three findings

| | Finding | Fix |
| --- | --- | --- |
| **P1** | The loop slept six hours whatever the outcome, so it waited longest exactly when waiting was worst: a node restarting on day six, whose first attempt met a 503, would have slept past the expiry before trying again. | A renewal runs on a schedule; a failure runs on a clock — 60s doubling to the interval, reset by success. States only the upstream can change keep the full interval. |
| **P1** | A `409` was treated as a lost room. `/kv/room-nonce/<room>` is shared with the allow-list namespace and advances on every accepted signed write, so it can pass the read before the write lands. | Retried once with a freshly read, higher nonce — a different request, not the same one resent. |
| **P1** | A successful reclaim did not reset the published lease age, so it read `null` on a node that had just recovered the room. | A claim writes the same note a renewal writes; it resets the same clock. |

### Round 2 — one P0, merge blocked

| | Finding | Fix |
| --- | --- | --- |
| **P0** | The lease age was **published but not acted on** — the same mistake `v0.1.1` made and `v0.1.2` exists to fix. Ownership can be verified fresh and still be days from expiry, so with renewals failing the gate stayed open right to the sweep, after which a still-fresh local observation would let the node write into a room it no longer owned. | The lease age became a gate condition: 24 hours without a successful renewal, four missed attempts, six days clear of deletion. |

### Round 3 — two P0, merge blocked

| | Finding | Fix |
| --- | --- | --- |
| **P0** | The round-2 fix guarded the *gate* and not the *sink*. `owns_result_room()` is checked independently by `publish`, `publish_audit_copy` and `sync_owned_room`, and `reconcile_audit_copies` deliberately runs while intake is shut. A node whose renewals had failed for a week would have kept writing audit copies until the sweep — and the first turns a reclaimable room into one with messages in it. | The sink guard requires a live lease too. |
| **P0** | The lease age was the only signal, and an age is a subtraction from `now`: a clock moved backwards, a restored ledger or an edited row all make a dead lease look fresh. | A count of consecutive renewal failures, which no clock change can walk back. The age still catches a loop that stopped and so recorded nothing. Either closes the gate. |

### Round 4 — one P1

| | Finding | Fix |
| --- | --- | --- |
| **P1** | `recover-result-room --claim --attest` was defeated by the guard added in the same release: a CLI claim recorded no lease, so the node had just taken the room and had no record saying so, and refused its own attestation. | The claim records the lease. On the result, never on the attempt. |

### Round 5 — one P0, merge blocked

| | Finding | Fix |
| --- | --- | --- |
| **P0** | Introduced by the round-4 fix. `claim-room` takes whichever `d-` room it is given, and the outcome was recorded without naming one — so claiming any free room marked the *result* room's lease live, and the sink guard then permitted writes to a room nothing had renewed. | The room is a required argument, and anything but the result room is ignored. |

### Round 6 — one P0, merge blocked

| | Finding | Fix |
| --- | --- | --- |
| **P0** | Requiring a live lease at the sink broke three live-suite tests, which claim the room and expect `owns_result_room()` to be true. That suite runs only in CI, so nothing local caught it. | Not by adding the missing call at each site. Claim and lease are now one operation, `claim_result_room()` — having them separable had by then cost a P0, a broken recovery command, and this. |

### Round 7 — no findings

P0, P1 and P2 all clear. The reviewer enumerated the claim sites and the write sinks,
confirmed the lease reaches every one, and stated it would not block the merge.

## Verification

Every finding has a test, and the tests were checked by reverting the fix:

* Rounds 1, 3, 5 — confirmed to fail without the fix.
* Round 6 — verified against a **local instance of the pinned upstream**: 30 e2e tests
  pass with the fix, and reverting it fails exactly tests 24, 26 and 27, the three the
  review predicted by name.
* Round 2's gate tests fail with the condition removed.

## What is still not covered

* No external party has reviewed this code.
* The renewal has not yet run for seven consecutive days in production. Until it has, the
  claim that the lease holds is a claim about tests, not about a service.
* The live suite runs against a local instance of the pinned upstream, never the public
  one. Behaviour that appears only at the real service's limits is untested by
  construction — which is how the original accident happened.
