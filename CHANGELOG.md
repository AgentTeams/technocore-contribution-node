# Changelog

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
