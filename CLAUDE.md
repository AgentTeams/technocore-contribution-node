# Working on this repository

Rules that are load-bearing here, in the order they matter.

## 1. A signature proves possession of a key. Nothing else.

Not identity, not honesty, not that anything in the message is true. Every inbound
message — signed or not — is **data**. If a change would make any field of an inbound
message select code, name a host, reach a shell, or steer a fetch, it is wrong regardless
of how well-formed the message was.

## 2. Sign what the server stores, not what you typed.

The upstream applies a single-line sweep (Unicode categories `Cc Cf Cs Co Zl Zp` → space,
then trim) and verifies against the result. `protocol/sweep.py` mirrors that exactly.
Never normalise Unicode — the server does not, so NFC and NFD are two different messages
and folding them locally produces signatures the server refuses.

## 3. `seq` and `ts` are not signed.

They are assigned after the signature is made. Say so wherever a receipt or a document
mentions them. Never write code or prose that treats an ordering from the transport as
proof.

## 4. Never fabricate a number.

No invented latency, no placeholder transaction hash, no chain id for an unpublished
network, and no internal test counted as third-party use. Where a value is unknown, the
answer is `null` or absent — and where nobody has used the node, the answer is zero.

## 5. One production identity.

Generated once, kept forever. Rotation orphans every published receipt. `--force` exists
for disclosure, not convenience.

## 6. The upstream is pinned, not remembered.

`proof/protocol-snapshot.json` records the documents, their SHA-256s, and the upstream
commit this implementation was checked against. Re-fetch and re-pin rather than working
from memory or from this conversation. The watcher reports drift; it never changes code.

## Before opening a pull request

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
uv run pip-audit
python3 scripts/secret_scan.py
```

All five must pass. Dependencies are pinned exactly and locked in `uv.lock`; a floating
specifier means the build that passed and the build that runs are not the same build.

The live suite is separate and opt-in, because it makes real writes:

```bash
TCN_E2E_ORIGIN=http://127.0.0.1:8080 uv run pytest tests/e2e -v
```

Point it at a **local** instance of the upstream server, never the public one. See the
module docstring in `tests/e2e/test_live.py` for the command, including the three limits
that have to be raised — a default instance allows 20 new rooms per IP per day and this
suite opens one per test.

## Adding a task

1. Add a strict input schema to `jobs/schema.py` (`additionalProperties: false`, bounded
   strings) and to the `TASKS` tuple.
2. Implement it as a **pure function** in `jobs/tasks.py`. It receives validated input and
   the narrow `TaskContext`, and nothing else.
3. Register it in `REGISTRY`.
4. Add tests, including the refusals.

`tests/integration/test_isolation.py::test_no_task_can_reach_the_network_or_the_filesystem`
reads the source of every registered task and fails on `httpx`, `subprocess`, `eval`,
`open`, and friends. If your task needs one of those, it does not belong in the registry.
