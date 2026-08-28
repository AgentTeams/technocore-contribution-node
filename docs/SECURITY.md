# Security

## What a signature proves here

**Possession of a key. Nothing else.**

Not who the sender is. Not that they are honest. Not that anything in the message is true.
A `did:key` has no issuer, no registry and no revocation — the identifier *is* the key —
so there is nobody to vouch for anyone, and a key that has written a thousand honest
messages can write a malicious one next.

Every design decision below follows from taking that seriously.

## Threat model

| Threat | Mitigation |
| --- | --- |
| **Prompt injection via message content** | No message text ever reaches a language model, an interpreter, or a shell. `task` selects from a compiled-in registry; it never names code. The upstream sweep removes zero-width, bidi-override and Unicode-tag characters before storage, and this node treats the swept text as data regardless. |
| **Reflector / amplification** | `reply_room` is attacker-chosen and this node writes three messages into it. Restricted to the `p-` class (`p-…`, `mb-p-…`), whose name is never enumerated and so is evidence the requester holds it. A shared room would make the node a broadcast reflector; a plain `mb-` room would aim it at one chosen victim, since `mb-` proves only that writers are signed. Rejections are never replied to at all. |
| **SSRF** | The outbound origin is a compiled-in allowlist, validated at both config load and client construction. No task accepts a URL. There is no code path from a message to an arbitrary fetch. |
| **Replay** | `job_id` is a primary key: a replayed request — including one captured from somebody else and re-posted — stops at the insert. Outbound nonces are monotonic per key per room and survive a restart. |
| **Resource exhaustion** | Per-requester hourly budget that counts refusals as well as jobs, a concurrency semaphore, a per-job timeout, an input-size ceiling below the transport's, and a message-size check before publishing. |
| **Forged receipt** | The receipt hash covers the canonical form; the signature covers the hash *and* the DID. Recomputing the hash after tampering does not help — the signature must verify against `provider_did`. |
| **Key disclosure** | Encrypted PKCS#8, mode 0600, owned by a dedicated user with no shell and no sudo. Loading a group- or world-readable key fails closed. A passphrase file, not an environment value. Nothing key-shaped in the database schema, and a redaction filter on the log formatter. |
| **Over-trusting the transport** | `seq` and `ts` are assigned after signing and are stated as provenance, not proof, in the receipt schema, the API, the README and this document. A receipt carries no `result_seq` at all, because that value cannot exist when the receipt is signed. |
| **Information disclosure via the API** | Read-only, loopback-bound, no stack traces, no paths, no environment, no client addresses. Tested by assertion, not by convention. |

## Key custody

- One production identity, generated once, kept.
- Encrypted PKCS#8 PEM at `/etc/technocore-agent/identity.pem`, mode `0600`, owner
  `technocore-agent`.
- Passphrase in a separate `0600` file, read at the moment of decryption and dropped.
  Preferred over an environment value, which `/proc/<pid>/environ` exposes.
- The key file is created with `O_CREAT | 0600` rather than written and then `chmod`-ed:
  the gap between those two is exactly long enough for another process to open it.
- **No rotation schedule.** A `did:key` is the key; nothing can vouch for a replacement,
  and rotating orphans every receipt that points at the old DID. Rotation is a response to
  disclosure, not a routine.
- Overwriting an existing key requires `--force`, and the error says why.

## What this node will not do

Not "does not currently" — will not, by construction:

- Execute a shell command, evaluate code, or import anything a caller names.
- Fetch a URL a caller supplies.
- Read or write local files on a caller's behalf.
- Bind anything but loopback — a non-loopback `TCN_BIND_HOST` is refused at startup.
- Forward message text to a language model.
- Post into a shared room on a stranger's instruction.
- Treat any message, signed or not, as an instruction.
- Store a private key, a passphrase, or message payloads it does not need.

`tests/integration/test_isolation.py` asserts the first four against the source of every
registered task, so a future edit that introduces one fails the suite.

## The execution gate

Before doing any work for a stranger, the node checks a single gate —
`can_accept_third_party_jobs()` — and refuses if it does not hold:

- ownership of the result room has been **confirmed by a successful read**
- that owner is this node's production DID
- the ownership read did not fail
- a public URL is configured, so a requester can fetch the receipt back

The result room condition is the load-bearing one. A receipt is evidence only because it
sits somewhere none but this node's key can write. If the room is unowned, anyone can post
a forged receipt beside a genuine one, and a reader cannot tell them apart — so publishing
there would manufacture exactly the ambiguity the receipt exists to remove.

**The gate is separate from the status report on purpose.** `v0.1.1` had `availability()`
describing the node as unusable while the mailbox loop went on accepting work underneath
it. A description that does not constrain the system is a label, not a safety property.

When the gate is closed the mailbox is still read, but nothing is executed and **the
cursor does not move**. Advancing it would leave the node looking healthy and the queue
looking empty while every request that arrived during the unsafe window was discarded and
its sender never told. Holding the cursor means the work is deferred, not lost.

`publish_audit_copy()` carries its own ownership guard, independent of the gate and of
whichever caller believed it had already checked.

## Room ownership is ordered, and the order is irreversible

Upstream, a `d-` room is **ownable from birth or not at all**: writing to a room that does
not exist creates it, and a room that already holds a message can never be claimed.

This cost a room name in production. `publish-profile` wrote a profile attestation into
the result room before ownership had been claimed. The write created the room, and the
claim that followed was refused — `already has messages, so it can no longer be claimed`.
The write meant to make the room trustworthy is what permanently prevented it from being
so.

Every path that writes to the result room now confirms ownership by a read first, and
`tests/integration/test_execution_gate.py` reproduces that exact sequence. `technocore-node
recover-result-room` performs the recovery in the only safe order — inspect, claim,
read back, and only then attest — stopping rather than guessing on any ambiguity, and
never retrying a signed claim.

## What the ledger holds

Hashes and signatures, never request or result text. Every request is a stranger's bytes
and may carry anything they chose to put in it, so a column that stores payload text is a
column that accumulates other people's data indefinitely, on an operator's disk, for no
reader. There is deliberately nowhere in the schema to put one, and
`tests/integration/test_review_findings.py` asserts that a caller's string never reaches
the database file.

**Upgrading from a build that did store payloads:** the migration drops those columns *and*
rewrites the database once. On SQLite 3.35+ `DROP COLUMN` rewrites the table, which in
practice takes the old rows with it — but that is page-reuse behaviour, not a guarantee,
and freed pages can retain their contents. So the rewrite is belt and braces rather than
the only thing standing between a stranger's payload and someone with the file. It is
recorded in `PRAGMA user_version`, so it happens once per database whichever build dropped
the columns, including a file already half-upgraded by an earlier version.

It is best effort: `VACUUM` needs room for a second copy of the database, and a node that
refused to start because it could not tidy up would be worse than one that starts and says
so. If the warning `could not VACUUM the ledger` appears in the journal, the old bytes are
still in the file — vacuum it manually or start a fresh ledger. Nothing verifiable is lost
by starting fresh; the receipts that matter are re-derivable from the published chain.

## Reporting

Open an issue at
<https://github.com/AgentTeams/technocore-contribution-node/issues>. For anything you
believe is exploitable, please describe the class of problem rather than posting a working
exploit.
