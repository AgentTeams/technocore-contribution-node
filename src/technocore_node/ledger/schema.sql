-- Technocore Contribution Node — evidence ledger.
--
-- Technocore rooms are a ring and notes expire after a week of silence, so the upstream
-- cannot be the record of what this node did. This database is. It holds hashes and
-- signatures rather than payloads: enough for any third party to re-verify a receipt
-- chain, and no more than that, because the requests come from strangers.
--
-- No private key material is stored here. Ever.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS identities (
    did              TEXT PRIMARY KEY,
    fingerprint      TEXT NOT NULL UNIQUE,
    public_key_hash  TEXT NOT NULL,          -- sha256 of the 32 raw public-key bytes
    created_at       TEXT NOT NULL,
    active           INTEGER NOT NULL DEFAULT 1,
    label            TEXT
);

CREATE TABLE IF NOT EXISTS protocol_snapshots (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at          TEXT NOT NULL,
    source               TEXT NOT NULL,       -- the origin the documents came from
    sha256               TEXT NOT NULL,       -- digest over the whole source set
    per_source_json      TEXT NOT NULL,       -- {name: sha256} for each document
    upstream_commit      TEXT,
    service_version      TEXT,
    limits_json          TEXT,
    compatibility_status TEXT NOT NULL,       -- compatible | changed | unknown
    changed_from_prev    INTEGER NOT NULL DEFAULT 0,
    diff_summary         TEXT
);
CREATE INDEX IF NOT EXISTS idx_snapshots_captured ON protocol_snapshots (captured_at DESC);

CREATE TABLE IF NOT EXISTS messages (
    local_event_id        TEXT PRIMARY KEY,
    direction             TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    room                  TEXT NOT NULL,
    did                   TEXT NOT NULL,
    nonce                 INTEGER,
    normalized_text_sha256 TEXT NOT NULL,     -- the hash only; never the text itself
    signature             TEXT,
    technocore_seq        INTEGER,
    technocore_ts         TEXT,
    status                TEXT NOT NULL,      -- pending | confirmed | failed | received
    error_code            TEXT,
    created_at            TEXT NOT NULL,
    confirmed_at          TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_room_seq ON messages (room, technocore_seq);
CREATE INDEX IF NOT EXISTS idx_messages_nonce ON messages (did, room, nonce DESC);

CREATE TABLE IF NOT EXISTS jobs (
    -- Globally unique, not per-requester: it is also the public receipt identifier at
    -- GET /v1/receipts/<job_id>, which would be ambiguous otherwise. A collision from a
    -- different requester is refused and recorded, never silently dropped.
    job_id           TEXT PRIMARY KEY,
    protocol_version TEXT NOT NULL,
    requester_did    TEXT NOT NULL,
    provider_did     TEXT NOT NULL,
    request_room     TEXT NOT NULL,
    reply_room       TEXT NOT NULL,
    request_seq      INTEGER,
    request_hash     TEXT NOT NULL,
    task_type        TEXT NOT NULL,
    status           TEXT NOT NULL,           -- received|validated|claimed|running|completed|failed|rejected
    received_at      TEXT NOT NULL,
    claimed_at       TEXT,
    completed_at     TEXT,
    failed_at        TEXT,
    latency_ms       INTEGER,
    internal_test    INTEGER NOT NULL DEFAULT 0,
    failure_code     TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_requester ON jobs (requester_did);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status);
CREATE INDEX IF NOT EXISTS idx_jobs_received ON jobs (received_at DESC);

CREATE TABLE IF NOT EXISTS results (
    job_id             TEXT PRIMARY KEY REFERENCES jobs (job_id) ON DELETE CASCADE,
    result_hash        TEXT NOT NULL,
    status             TEXT NOT NULL,          -- ok | error
    summary_bytes      INTEGER NOT NULL,       -- size of the summary, never the summary
    provider_signature TEXT NOT NULL,          -- the RESULT's detached signature
    result_seq         INTEGER,
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id         TEXT PRIMARY KEY,
    job_id             TEXT NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    requester_did      TEXT NOT NULL,
    provider_did       TEXT NOT NULL,
    request_hash       TEXT NOT NULL,
    result_hash        TEXT NOT NULL,
    provider_signature TEXT NOT NULL,
    receipt_hash       TEXT NOT NULL,
    receipt_json       TEXT NOT NULL,
    technocore_seq     INTEGER,          -- seq of the copy in the requester's reply room
    -- The copy in this node's OWNED room: the auditable one, because only this node's
    -- key can write there.
    --
    -- The row is written BEFORE either publish, so a crash between doing the work and
    -- announcing it leaves a record that says what is still owed. Written afterwards, the
    -- job would already be marked complete, the duplicate check would suppress any retry,
    -- and the receipt would simply be gone.
    audit_seq          INTEGER,
    -- owed | published | quarantined. Quarantined rows are excluded from the retry queue
    -- so that one unpublishable receipt cannot starve every receipt behind it.
    audit_state        TEXT NOT NULL DEFAULT 'owed',
    audit_attempts     INTEGER NOT NULL DEFAULT 0,
    audit_error        TEXT,
    internal_test      INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_job ON receipts (job_id);

CREATE TABLE IF NOT EXISTS metrics_snapshots (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at           TEXT NOT NULL,
    total_jobs            INTEGER NOT NULL,
    completed_jobs        INTEGER NOT NULL,
    failed_jobs           INTEGER NOT NULL,
    unique_requester_dids INTEGER NOT NULL,
    repeat_requester_dids INTEGER NOT NULL,
    internal_test_jobs    INTEGER NOT NULL,
    p50_latency_ms        INTEGER,
    p95_latency_ms        INTEGER
);

-- Refusals. Recorded so a requester can be told why through the read-only API instead of
-- by a message this node posts: replying to a malformed request would let a stranger
-- choose the room this node writes into, which is a reflector, not a service.
CREATE TABLE IF NOT EXISTS rejections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id        TEXT,
    requester_did TEXT,
    code          TEXT NOT NULL,
    detail        TEXT,
    request_room  TEXT,
    received_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rejections_requester ON rejections (requester_did, received_at);
CREATE INDEX IF NOT EXISTS idx_rejections_job ON rejections (job_id);

-- Observed deployment state: what this node has actually seen about its own reachability.
--
-- Kept because the alternative is prose. Whether a third party can reach this node is a
-- fact about the upstream, not a sentence for an operator to remember to update — so the
-- API reports what the node observed, with when it observed it, rather than a claim
-- somebody typed once and left behind.
CREATE TABLE IF NOT EXISTS deployment_state (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL
);

-- The high-water nonce each requester has spent over the HTTP lane.
--
-- A nonce orders one requester's submissions and lets an old one be rejected, but the
-- requester chooses it, so on its own it proves nothing. It is half of a pair: this table
-- refuses a nonce that does not advance, and the signature covers a hash of the body, so
-- a captured request can be neither replayed nor edited. Per DID, because one requester's
-- counter is no business of another's.
CREATE TABLE IF NOT EXISTS http_nonces (
    requester_did TEXT PRIMARY KEY,
    last_nonce    INTEGER NOT NULL,
    updated_at    TEXT NOT NULL
);

-- Per-room read cursors, so a restart resumes where the poller stopped rather than
-- reprocessing a room from its oldest retained message.
CREATE TABLE IF NOT EXISTS cursors (
    room       TEXT PRIMARY KEY,
    last_seq   INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
