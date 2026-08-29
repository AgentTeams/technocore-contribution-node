# Changelog

## v0.1.3 — 2026-08-30

A claim is a lease. Nothing was renewing it.

### The gap

`v0.1.2` made every path check whether the result room is owned by this node. None of
them kept it that way. Ownership upstream is a **note**, and the upstream deletes anything
with no write for seven days — `retention_seconds: 604800` in `/.well-known/agent.json`,
with no exemption for the signed namespaces. So a room claimed and then left alone reverts
to "an ordinary open room", and the first stranger to write to it makes it permanently
unclaimable.

That is the accident of 2026-08-28 again, with a seven-day fuse instead of an immediate
one — and it would have fired while the node was switched off after the first one, because
`run_mailbox` was the only loop and intake is disabled.

The room was reclaimed on 2026-08-30 after the upstream's 24-hour sweep freed the name.
Without this change it would have been lost again by 2026-09-05.

### Added

- **`Node.run_ownership_lease()`** — renews every 6 hours, started **unconditionally**,
  independent of `TCN_MAILBOX_ENABLED`. Eight renewals fit inside the expiry window, so
  the lease survives a day of failures rather than depending on the next one working.
- **`TechnocoreClient.refresh_room_ownership()`** — deliberately not `claim_room`. That
  one carries `if_absent`, which is right for a first claim and makes renewal impossible;
  this one omits it, which is what lets it overwrite. It therefore refuses to run unless
  the note it is about to overwrite already holds this node's own DID: two callers, two
  guarantees — one can only create, the other can only renew.
- **A lapsed lease is reclaimed**, through `claim_room`, which writes only to the
  ownership note and never to the room. Writing to the room is what made it unclaimable
  the first time. A room that can no longer be claimed is reported and left alone.
- **Claiming an unrelated room started the result room's lease.** `claim-room` takes
  whichever `d-` room it is given, and the lease outcome was recorded without naming one —
  so claiming any free room marked the result room's lease live, and the sink guard, newly
  taught to require a live lease, would then permit writes to a room nothing had renewed.
  The room is a required argument now, so it is not a mistake a caller has to remember not
  to make.
- **The recovery command was defeated by its own guard.** `recover-result-room --claim
  --attest` is the documented procedure — inspect, claim, read back, attest — and a CLI
  claim recorded no lease, so the node had just taken the room and had no record saying
  so. The sink guard added in this same release then refused the attestation. A safe
  failure, and a broken procedure.
- **The lease guards the write, not only the gate.** `owns_result_room()` is checked
  independently by `publish`, `publish_audit_copy` and `sync_owned_room`, and
  `reconcile_audit_copies` runs even while intake is shut so receipts owed from before a
  closure still land. Asking only who owns the room would have let a node whose renewals
  had failed for a week keep writing audit copies until the sweep — and the first turns a
  reclaimable room into one with messages in it, which can never be claimed again.
- **A failure count as well as an age.** An age is a subtraction from `now`, so a clock
  moved backwards, a restored ledger or an edited row makes a dead lease look fresh. The
  count cannot be walked back by changing the time; the age catches a loop that stopped
  and recorded nothing. Either closes the gate, a renewal clears both.
- **The lease age is a gate condition.** The gate closes after 24 hours without a
  successful renewal — four missed attempts, six days clear of the upstream's deletion.
  Publishing the number and stopping there would have repeated the `v0.1.1` mistake this
  project spent `v0.1.2` fixing: ownership can be verified fresh and still be days from
  expiry, and with renewals failing the gate would have stayed open until the sweep, after
  which a still-fresh local observation would let the node write into a room it no longer
  owned. The original accident, reached by a different road.
- **`ownership_lease` in `/v1/info`** — when it last renewed and how long the upstream
  keeps a note, reported beside the `stop_reason` that acts on it.

### Fixed

- **A failed renewal waited out a full interval.** The loop slept six hours whatever the
  outcome, so it waited longest exactly when waiting was worst: a node restarting on day
  six, whose first attempt met a 503, would have slept past the expiry before trying
  again. A renewal runs on a schedule; a failure now runs on a clock — 60s, doubling to
  the interval, reset by a success. `owned_by_other` and `unclaimable` keep the full
  interval, because neither is fixed by asking again in a minute.
- **A nonce conflict was treated as a lost room.** `/kv/room-nonce/<room>` is shared with
  the allow-list namespace and advances on every accepted signed write, so it can pass
  the read before the write lands. A `409` there means the counter moved, not that the
  room is gone; it is retried once with a freshly read, higher nonce — a different
  request, not the same one resent.
- **A reclaim did not reset the published lease age.** A claim writes the same note a
  renewal writes, so it resets the same clock. Recording only renewals left the lease age
  reading `null` on a node that had just recovered the room.
- The test double for the upstream returned a constant replay counter, so a renewal that
  reused a nonce passed locally and would have been refused by the real server. It now
  advances the counter and rejects a nonce that does not clear it.

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
