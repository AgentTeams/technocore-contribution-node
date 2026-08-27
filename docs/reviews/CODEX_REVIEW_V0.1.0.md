# Pre-release review, v0.1.0

## What this was, and what it was not

This was a **local Codex CLI review**: `codex exec --sandbox read-only`, driven from the
operator's machine against a working copy of this repository, over nine rounds.

**It was not a GitHub Pull Request Review.** No reviewer approved PR #1 through GitHub, no
`Approved` status exists on it, and nothing here was checked by a second person. The
reviewer was a language model given read-only access to the source, told to look for
specific classes of defect, and asked each round to verify its own previous findings had
actually been fixed.

Read it as what it is: an adversarial pass that found real bugs, not an audit and not a
substitute for independent human review. Several findings below were things the author's
own tests did not catch, which is the argument for having done it; the fact that a tenth
round might have found more is the argument against treating it as complete.

| | |
| --- | --- |
| Tool | `codex-cli` 0.142.5 |
| Model | `gpt-5.1-codex-max`, reasoning effort `high` |
| Mode | `--sandbox read-only` (no writes, no network egress on the reviewer's part) |
| Rounds | 9 |
| Final verdict | no P0, no P1 — merge approved |
| Raw transcripts | retained in a private operator archive, not published; SHA-256 below |

## Findings and resolutions

Severity is the reviewer's: **P0** = must fix before merge, **P1** = should fix.
Every finding below was fixed before merge; none was accepted as-is or waived.

### Round 1 — 1 × P0, 6 × P1

| # | Finding | Fix | Test |
| --- | --- | --- | --- |
| P0 | `results.result_summary` and `messages.normalized_text` persisted requester-supplied text. Written, never read: anything a stranger put in `input.value` accumulated on the operator's disk indefinitely — while `schema.sql` said the ledger keeps hashes rather than payloads. | Columns removed; migration drops them from an existing database. `record_result` stores `status` and `summary_bytes` instead. | `test_no_request_or_result_text_is_ever_persisted`, `test_the_schema_has_nowhere_to_put_a_payload` |
| P1 | Canonicalisation failures escaped the refusal path. An unpaired surrogate parses, passes the schema, and is not UTF-8 — it surfaced as an unhandled `UnicodeEncodeError`: no refusal record, no signed answer, no rate-limit accounting. | `canonicalize()` rejects lone surrogates; `parse_and_validate` converts `CanonicalJSONError` to `RejectedJob`. | `test_an_unpaired_surrogate_is_a_refusal_not_a_crash` |
| P1 | Duplicate JSON keys were canonicalised away. Python keeps the last; a verifier keeping the first reads the same signed bytes differently, and the signature verifies for both. | `parse_strict()` rejects duplicates via `object_pairs_hook`. | `test_duplicate_object_keys_are_refused` |
| P1 | `job_id` was checked without the requester, so claiming an id first silently erased another agent's job — not executed, not answered, not recorded. | Collision with a different DID is refused `job_id_taken`; same-requester repeat stays idempotent. | `test_another_requesters_job_id_is_refused_loudly` |
| P1 | `receipts.provider_signature` stored the receipt's own signature instead of the result's. `receipt_json` stayed correct, so nothing looked broken. | Stores `receipt["provider_signature"]`. | `test_the_receipt_row_stores_the_results_signature` |
| P1 | Log redaction missed the JSON-encoded forms — `"token":"…"`, `Authorization: Bearer …` — which is the shape most likely to be logged. | Patterns reordered and widened; scheme rules run before the generic one. | `test_json_encoded_credentials_are_redacted` |
| P1 | The protocol watcher fetched `api.github.com` outside the central outbound allowlist. | One allowlist, checked on the single method that makes a request. | `test_every_origin_this_node_contacts_is_allowlisted` |

### Round 2 — 2 × PARTIAL, 1 new P1

| # | Finding | Fix | Test |
| --- | --- | --- | --- |
| PARTIAL | The ledger rewrite ran only when that startup dropped a column, so a database an earlier build had already stripped would never be rewritten. | Conditioned on the file's own `PRAGMA user_version`; runs once per database. | `test_a_file_already_stripped_by_an_older_build_is_still_rewritten` |
| PARTIAL | The `job_id` check ran before the insert, so two requesters could both pass it and the loser was still dropped silently. | Post-insert re-check refuses with `job_id_taken` unless the winner is the same requester. | `test_losing_the_insert_race_still_refuses_a_foreign_job_id` |
| P1 | `SECURITY.md` and a test comment still said the migration does not scrub, which stopped being true. | Documentation corrected; the test now asserts what is true rather than an unachievable precondition. | — |

### Round 3 — 2 × P1

| # | Finding | Fix | Test |
| --- | --- | --- | --- |
| P1 | `RECEIPT_SCHEMA` is `additionalProperties: false` and declared none of the six settlement fields the docs said it reserved, so `TechnocoreAdapter.annotate_receipt` produced receipts invalid against it. | Fields declared and named once in `RESERVED_NETWORK_FIELDS`. | `test_the_reserved_network_fields_are_declared_not_merely_described` |
| P1 | Receipts went only to the requester's reply room, while the protocol doc said they also reach the node's owned room. | Non-test receipts publish to both. | `test_24_a_receipt_reaches_the_owned_room_as_well_as_the_reply_room` |

### Round 4 — 2 × P0, 2 × P1

| # | Finding | Fix | Test |
| --- | --- | --- | --- |
| P0 | The receipt was recorded *after* publishing. The job was already marked complete, so a crash in between left a completed job whose receipt did not exist — and whose duplicate check suppressed every retry. | `record_receipt` runs before either publish. | `test_a_receipt_is_durable_before_it_is_announced` |
| P0 | The reconciler wrote `audit_seq` after publishing, so a crash between the two republished on the next pass. | `sync_owned_room()` reads the room and marks what is already there before republishing. | `test_27_a_copy_that_landed_before_a_crash_is_not_published_twice` |
| P1 | A receipt that could never publish sat at the head of an ordered queue and stalled everything behind it. | Attempts counted, queue ordered by fewest attempts, quarantine after five. | `test_a_receipt_that_never_publishes_is_quarantined_not_left_blocking` |
| P1 | `ARCHITECTURE.md` claimed a restart resumes a job mid-flight; `CONTRIBUTION_PROTOCOL.md` promised retries with no mention of quarantine. | Both corrected. | — |

### Round 5 — 1 × P0, 3 × P1

| # | Finding | Fix | Test |
| --- | --- | --- | --- |
| P0 | `ADD COLUMN … DEFAULT 'owed'` marked every pre-existing receipt as outstanding, including ones already published — a whole ledger's worth of re-announcements. | `_backfill_audit_state()` derives the state from `audit_seq`; the queue also excludes any row with a seq. | `test_a_migrated_database_does_not_re_announce_what_it_already_published` |
| P1 | The room sync matched on `job_id` alone, so any message carrying that id could mark a different receipt publicly auditable. | Matches the stored `receipt_hash` too. | `test_sync_matches_the_receipt_not_merely_the_job_id` |
| P1 | Quarantine caught only JSON syntax errors; an empty object, an empty array or a bare string would be published as-is or raise inside the publisher. | `_unpublishable()` validates type, `job_id`, hash and schema first. | `test_a_stored_row_that_is_not_a_receipt_is_quarantined` |
| P1 | README described `verify_receipt_chain`'s `job_id` form and `/v1/receipts` in terms of publication rather than storage. | Corrected. | — |

### Round 6 — 2 × P1

| # | Finding | Fix | Test |
| --- | --- | --- | --- |
| P1 | Three documents promised a loopback-only bind and nothing enforced it — a non-loopback host was one environment variable away. | `LOOPBACK_HOSTS`; `load_settings()` refuses anything else. | `test_a_non_loopback_bind_is_refused` |
| P1 | The receipt carried `result_seq`, which was always null and always would be: it is signed before the result is published. | Removed from the builder, the schema and the docs; the reason recorded beside `request_seq`. | `test_a_receipt_carries_no_result_seq` |

### Round 7 — 2 × P1

| # | Finding | Fix | Test |
| --- | --- | --- | --- |
| P1 | `reply_room` accepted any `mb-` room. That class means writes are signed, not that the requester owns the room — so a stranger could aim three of this node's messages at somebody else's public mailbox. | Restricted to the `p-` class (`p-`, `mb-p-`, `e-p-`), whose name is never enumerated and so is evidence of holding it. | `test_a_room_the_requester_cannot_prove_they_hold_is_refused` |
| P1 | `OPERATIONS.md` opened by saying the node runs "deliberately not alongside anything else on the host", the opposite of its design. | Corrected to describe isolation rather than absence. | — |

### Rounds 8 and 9 — 1 × P1 each

Stale copies of the superseded `reply_room` rule: first in the dashboard served at `/`,
then in the README diagram and a test fixture string. Both wording-only; the rule itself
and every enforcing surface were already correct. Round 9 confirmed the old rule appears
nowhere and returned the final verdict.

## Where the reviewer was pushed back on

Not every reviewer observation was accepted as stated. In round 5 the reviewer reported
that bytes survive `DROP COLUMN`; measured on SQLite 3.45 that operation rewrites the
table and takes them with it, so the accompanying test was written to assert what is true
— that the rewrite runs — rather than a precondition that does not hold, and
`SECURITY.md` describes the `VACUUM` as belt-and-braces rather than the only protection.

## Verification at merge

```
pytest        264 passed, 30 skipped
pytest e2e     30 passed against a local instance of the upstream server
ruff check     All checks passed
ruff format    66 files already formatted
mypy           Success: no issues found in 35 source files (strict)
pip-audit      No known vulnerabilities found
secret scan    clean
```

## Raw transcripts

The nine rounds' full transcripts are kept in a **private operator archive**, not in this
repository: they quote server filesystem paths from the host the review ran on. They were
scanned before archiving and contain no private key material and no OAuth or API tokens —
the matches a scanner flags in them are this repository's own detection patterns and its
deliberately fake test fixtures.

```
archive : codex-v0.1.0-logs.tar.zst   (14 transcripts + manifest, zstd)
sha256  : 97f69c19200fc3cce42a316698b7112235a01967dacd9eaa2fe129239b99f68b
```

Anyone reproducing this review can run the same tool against this repository; the prompts
used are summarised by the finding categories above.
