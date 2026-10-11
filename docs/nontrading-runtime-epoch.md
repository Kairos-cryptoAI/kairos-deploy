# Isolated non-trading data runtime

This path creates a new database and Redis epoch. It is not a restart, repair,
acknowledgement, or migration of the historical primary or its queue.

The operator must first verify the exact signed `main` source and green CI.
`scripts/runtime_epoch_controller.py` is plan-only without `--execute`.
Execution additionally binds the reviewed Deploy revision, the stopped legacy
Redis container identity, the accepted immutable backup, and a closed-minute
catch-up deadline. The controller records a create-only epoch lease; it must not
be removed to bypass a failed or still-running epoch.

## Data boundary

- The legacy PostgreSQL and Redis containers remain stopped. The controller may
  inspect their exact metadata but never starts them, mounts their volumes,
  issues SQL/Redis commands to them, or replays their queue.
- The accepted backup is restored into a disposable, separately owned clone.
  Only independently verified one-minute `ClosedBarEventV1` history for
  BTC/ETH/SOL/BNB/XRP is copied to the new `event_audit`.
- Identity, canonical hashes, unique contiguous chains, row/byte/time bounds,
  and accepted per-symbol anchors are checked before the seed transaction
  commits. History does not create inbox, outbox, cursor, order, or effect rows.
- Bounded catch-up uses free official Binance public klines. Two observations
  must agree; incomplete, changed, gapped, oversized, or non-final bars fail
  closed. Catch-up history remains audit-only.
- A new backup is restored to another isolated clone. All 39 public tables,
  sequence state, and PostgreSQL physical/index integrity must pass before
  continuous delivery is admitted. Any final audit-only catch-up after that
  snapshot is separately recorded, not represented as part of its restore proof.

## Continuous delivery boundary

Only freshly closed bars enter the new transactional outbox. Redis publication
uses an atomic identity/hash/stream receipt ledger: retry after acceptance
returns the same stream entry and a conflicting payload is rejected. A
least-privilege durable consumer validates bars and records completion before
transport acknowledgement; it cannot publish or mutate the outbox.

Separate producer and consumer database/Redis identities have no execution
writes. Runtime projections exclude administration and historical-source
credentials. A lifetime PostgreSQL advisory lock rejects a second supervisor.
Resource ownership labels, private file ACLs, immutable source snapshots,
offline wheels, no host ports, read-only container roots, memory/CPU/process
bounds, and bounded disposable phases are mandatory.

Qualification checks fresh progress across all five symbols, zero unresolved
inbox/pending outbox and no published record without matched completed inbox,
duplicate acceptance/delivery, permission denials, and a
controlled restart within this new epoch. Restart does not republish history.
Finite qualification is not a long-duration availability or trading proof.

## Forbidden starts and readiness

No strategy, Router, LLM, Macro, Risk, Execution, PAPER, LIVE, EVEDEX, or paid
provider process is started by this path. No order, position, stop-loss,
take-profit, or simulated trade is generated. Frozen research evidence and
historical unknown publication outcomes remain unchanged.

An accepted receipt means **working non-trading bar delivery only**.
`PAPER_QUALIFIED=false`, `ALPHA_READY=false`, `LIVE_READY=false`, and
`STRATEGY_POLICY=REJECT_ALL` remain in force. Failures retain owned evidence for
inspection; they do not authorize retries against the historical runtime.
