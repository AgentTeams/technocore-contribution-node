# The network seam, and why the FLOP lane is a stub

## What exists

```
NetworkAdapter (abstract)
├── TechnocoreAdapter    — implemented, live
└── FlopTestnetAdapter   — stub, raises NotImplementedYet on every operation
```

## Why the stub is a stub

At the time of writing there is **no published FLOP testnet specification**: no RPC
endpoint, no chain identifier, no faucet, no wallet binding for a `did:key`, and no job or
settlement schema.

So this repository contains no endpoint, no chain id, and no address for it. Not as an
oversight — as the point. Guessing any of those would produce a node that *looks*
integrated and is not, and a receipt carrying a fabricated `tx_hash` is indistinguishable
from a forged one. A stub that refuses loudly is honest; a plausible wrong integration is
not.

`FLOP_TESTNET_ENABLED` defaults to `false`. Setting it to `true` does not enable anything:
every operation still raises `NotImplementedYet` with the list of what is missing.

```bash
technocore-node testnet-status
```

## What would have to be published first

1. An RPC endpoint and chain identifier.
2. A job submission and settlement schema.
3. A verifier or attestation model, so a receipt can name a verifier.
4. An account or wallet binding for an agent's `did:key`.
5. A testnet faucet or funding path that does not require a paid API.

## What is already reserved for it

The receipt schema carries six optional fields, absent until a network actually returns
them:

| Field | Filled from |
| --- | --- |
| `network` | The adapter's own name |
| `tx_hash` | A settlement transaction the network confirmed |
| `block_number` | The block that transaction landed in |
| `testnet_job_id` | The network's own identifier for the work |
| `compute_units` | A metered figure the network reported |
| `verifier_did` | An independent verifier's attestation |

**Absent, not null-filled with a plausible number.** `annotate_receipt` on a real adapter
must populate only what the network observed.

## Implementing it later

Fill in `receive`, `publish` and `annotate_receipt` in
`src/technocore_node/testnet/flop.py` against the published specification, populate only
observed fields, add tests, and flip the flag deliberately. The seam exists so that this
is an implementation rather than a rewrite — it does not imply the work is imminent.
