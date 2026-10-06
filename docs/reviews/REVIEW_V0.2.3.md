# Pre-merge review — v0.2.3

Three rounds of adversarial review of the room-lifetime and backlog changes, on the pull
request before it merged. Fourteen findings: thirteen fixed, one recorded under "Not fixed"
in the changelog. The first two rounds each found P1s. The third found none.

## What this was, and what it was not

Each round was a separate Claude subagent, started from the same Claude Code session that
wrote the code. Each was given:

- the commit to review;
- read access to the repository;
- a local instance of the upstream server at the pinned commit;
- the instruction to report only defects with a concrete failure scenario, confirmed by
  running something.

Each later round was asked first to check that the previous round's fixes held, and then
to look for defects those fixes had introduced.

It was **not** a GitHub pull-request review, not an independent audit, and not a substitute
for one. Nobody outside this project has read this code. The reviewers' scripts are not
published; this file is the summary, and it names what was found.

## Findings

Severity:

- **P1** — a message skipped or handled twice, a documented claim the code does not keep,
  or a read storm against the upstream.
- **P2** — a narrower correctness or cost fault.
- **P3** — a fault that needs an upstream failure the upstream does not have.

Every code fix has a test confirmed to fail on the commit before it. The one exception is a
fix that removed code.

### Round 1 — five findings, on `10e53e6`

| | Finding | Fix |
| --- | --- | --- |
| **P1** | A room the upstream renumbers from 1 can keep its generation number, so neither the numbers nor the generation show the replacement. The probe compared only the room's tail and its generation. | The cursor is checked against the message this node recorded handling at it. |
| **P1** | Reads asked for no `limit`, and the upstream returns the *newest* 50 records after the cursor. A backlog lost its oldest messages without a word, and had since `v0.1.0`. | Reads take 200. A full read that starts past the cursor is caught up from the room's export. |
| **P2** | The node restarted on every new generation. The upstream writes a recreated room's first record before it bumps the generation, so a read between the two handled the message twice: two refusals for one line, both charged to the sender's budget. | A new generation is decided by the message at the cursor, not restarted on. |
| **P2** | The probe read the room's tail without a cursor. The upstream answers that read with 0 for an emptied room even when it kept the numbering, so the probe took the room for a replaced one, reset the cursor, and erased the gap accounting. | The probe reads from just before the cursor, where the upstream answers with the kept numbering. |
| **P2** | A probe that answered with no room still counted as a check for ten minutes. `True`, `"7"` and `-1` read as `seq` still moved cursors. | An unusable answer raises. A seq is a position only if it is one. |

### Round 2 — six findings, on `1cfc79d`

| | Finding | Fix |
| --- | --- | --- |
| **P1** | The upstream also stops a read at 1 MiB. A short read that started past the cursor was taken for ring loss. Against a local upstream, a job at seq 4 under 150 records of 12 KB was never handled, and 66 messages were recorded as aged out. | Any read that starts past the cursor is checked against the export, however many records it returned. |
| **P1** | With the gate shut and more than 200 messages waiting, every cycle downloaded the whole room and nothing slept: 622 exports, about 84 MiB, in five seconds against a local upstream. Underneath it was an older fault: a held loop re-read the mailbox as fast as the upstream answered. | A held loop waits 30 s between reads and downloads no backlog. |
| **P2** | The audit-room sync read one page before the reconciler posted. With 250 owed copies already in the room, three were posted again. | The sync reads the whole backlog. |
| **P2** | Inbound record ids carried the generation, which a renumbered room can repeat, so the new lifetime overwrote the old one's records. | Ids carry a per-room count of restarts. |
| **P2** | When a read returned records but none had a usable seq, its `last_seq` still moved the cursor. | `last_seq` moves a cursor only when the read returned nothing at all. |
| **P2** | `export_room` parsed a header with `str.isdigit`, which accepts `"²"` and then fails in `int()`. The parsed value was never used. | Removed. |

### Round 3 — three findings, on `0ad88bf`; no P0 or P1

The reviewer re-ran round 2's reproductions on this commit and found them fixed.

| | Finding | Fix |
| --- | --- | --- |
| **P2** | An open, idle loop spun when the upstream answered a long-poll at once instead of parking it, which it does once a few are parked for the same address: 1,691 polls in five seconds. This was pre-existing. | An idle cycle takes at least five seconds. |
| **P3** | A room renumbered from 1, under its old generation, and refilled past the cursor between two reads a few seconds apart is not detected: nothing in either read differs from an ordinary one. | Recorded under "Not fixed". It needs the upstream to lose a record it does not prune. |
| **P2** | The docs said a held mailbox downloads nothing, but the position check can still export the room once every ten minutes. | The docs say so. |

## Checked against the upstream itself

Besides the suite, the release was checked against a local upstream 0.14.5, running the
upstream's own reaper with its clock eight days ahead:

- A mailbox deleted and recreated while the node was polling had its next job read once,
  in order.
- A backlog of 250 was handled whole and in order.
- A job under 150 records of 12 KB, past what one read returns, was handled, and nothing
  was counted as lost.
- A held mailbox made one read in five seconds.
