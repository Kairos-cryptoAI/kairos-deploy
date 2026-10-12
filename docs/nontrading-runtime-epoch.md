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

## Single-attempt continuation after first catch-up failure

A continuation is an explicit, same-owner recovery attempt for the one isolated
epoch, not a new epoch or a general retry. It is eligible only when the first
bounded catch-up phase (`catchup-01`) failed; preserve that original failure
receipt, create-only lease, and phase configurations unchanged. Before
continuing, independently verify the signed operator-archive parent
`271354af42bb40004d55c1164ecf7363c83b9c1b` and the new signed clean `main`
HEAD with green CI. Reconfirm exact ownership of the
new PostgreSQL/Redis resources and mounts, and that no worker is active.

Before any continuation write, take a backup of the new target and restore it
to another isolated target. Verify all 39 public tables, sequence state, and
physical/index integrity against that backup. Rotate only the new epoch's
history credential through its fixed database role, using a private file
projection; never put credentials in CLI arguments or output. Worker runtime
dependencies must be executable from the dedicated bounded libraries mount
(`/runtime-libs`, `nosuid,nodev,exec`); keep `/tmp` separately bounded and
`noexec`. Any other failed phase, ownership mismatch, active worker, or failed
backup/restore check stops continuation. No legacy database, Redis, queue,
volume, or credential is changed. This procedure is specified here, not a
claim that continuation has executed or passed.

A second create-only continuation is limited to the recorded pre-backup
initializer failure of attempt `01`. It must bind that failure's exact hash,
preserve the original attempt directory, and retain the failed initializer's
metadata and log before removing only that stopped, owner-labelled helper.
Its named restore volume is preserved; any helper-only anonymous volume may
be removed with the helper. The initializer has only `CHOWN` and `FOWNER`
capabilities on its exact new-epoch volume and no network. An explicit tiny
PostgreSQL-data tmpfs prevents the image from creating another anonymous volume.
The pre-write backup/restore proof and every later gate remain mandatory.

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

## Exact R4 read-timeout recovery (R5)

`scripts/runtime_epoch_read_recovery.py` is plan-only by default. Its single
create-only attempt admits the exact stopped R4 container, failed status,
signed source, accepted recovery receipt and original latches. It does not
restart R4 or change an earlier attempt's evidence. The infrastructure cause
of R4's Redis read timeout is unconfirmed; the verified defect is fatal
handling of a transient consumer transport failure.

The admitted new epoch contains 336,429 audit rows, 5,336 published outbox
rows, and 5,331 completed inbox rows. Only the five fixed, already published
messages at open time 1791791760000 may be completed. Any other gap, partial
completion, hash conflict, lease, trading row or resource identity fails closed.
Before that write a fresh dump must pass full 32-table/sequence/history equality
and physical/index checks on a separately owned `transport05` restore clone.
Completion uses the existing durable consumer and its least-privilege identity:
no publication, history rewrite, group reset, lease reset or cursor reset.
The post-completion proof preserves every prior audit/outbox row, sequence,
completed inbox prefix, stream payload and known publication receipt.

Only after that proof does the path catch up audit-only history, take and
independently restore another fresh dump, then create one new R5 bar supervisor.
It must demonstrate fresh progress for all five symbols and a graceful,
same-container stop/start with another five-symbol advance. Existing queue
qualification already contains its one exact duplicate stream entry; this path
does not append another artificial duplicate to the working queue.

The worker-local Redis transport disables hidden client retries and uses a
one-second stream block, a six-second command bound, and at most three transport
failures per bounded recovery episode. An ambiguous new-message read first
drains that same consumer's pending entries before reading new messages again.
Completed inbox deduplication remains authoritative. Authentication, permission,
protocol, payload, database and integrity errors are not retried. Cancellation
propagates. Frozen Core, research sources and trading contracts are unchanged.
SIGTERM requests a fully drained cycle and creates a new immutable clean-stop
receipt; it does not interrupt an inbox transaction or overwrite a prior receipt.

Implementation and finite acceptance are not a claim of month-long uptime.
Boot and technical notifications must be separately bound to the accepted R5
receipt and exact signed sources. Trading and all readiness flags remain off.

## Feed outage handling and exact R5-to-R6 continuation

The later R5 failure is a distinct public closed-bar GET timeout. A successful
short observation or Redis fix is not proof that the feed path is resilient.
R6 retains every prior generation, source snapshot, latch and receipt.

The separate `runtime_epoch_feed_recovery.py` path is create-only and plan-only
by default. Its admitted pre-state is 339,618 audit rows, 5,795 outbox rows,
5,791 completed inbox rows, and exactly four fixed **unpublished** messages.
It requires a new full 32-table/sequence/five-chain isolated restore before
publishing those four once through the existing dispatcher and completing their
durable inbox/ACKs. Old publications and queue prefixes remain unchanged.
Only then does it perform audit-only backfill, another complete restore and
fresh five-symbol progression before/after a graceful same-container restart.
Legacy clusters, cursors and leases are never reset or connected for recovery.

The serving circuit recognizes only the admitted public-GET timeout. It keeps
the existing three attempts per GET round and waits with a capped 5/15/30/60s
backoff, five-second status heartbeat and cooperative stop. Its state is
`WAITING_SOURCE_NONTRADING`, not a fresh/healthy trading feed. Mixed timeout and
integrity/database failures remain fatal. HTTP rejection, TLS validation,
malformed payloads and other unadmitted failures are not converted into retries.

On source recovery, live catch-up is split into batches of at most 100 aggregate
bars; the cap is not raised after an outage. Each batch is flushed and fully
consumed before proceeding. `CATCHING_UP_NONTRADING` remains unready; only actual
watermarks at the current finalized target can yield `RUNNING_NONTRADING`.
Per-attempt failure diagnostics are create-only, so repeated timeouts do not
overwrite an earlier failure receipt. Offline fault tests exercise the actual
supervisor loop, timeout/defer/recovery, same-consumer lifecycle, mixed-failure
rejection, capped batches and cancellation without any trading authority.

Source/test completion does not imply native R6 acceptance, external alert
delivery, OS-reboot qualification or long-duration availability. Those require
their separate receipts. All project readiness flags remain false.
