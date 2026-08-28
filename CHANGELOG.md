# Changelog

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
  result-room ownership confirmed by a successful read, owner equal to this node's DID, no
  read error, and a public URL configured.
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
