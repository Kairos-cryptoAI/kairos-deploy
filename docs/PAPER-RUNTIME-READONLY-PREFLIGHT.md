# PAPER target-role and full-history restore preflight

This engineering slice implements read-only observation of the one fixed
`kairos-paper-gate` / `kairos` primary and restoration of a fresh backup into a
generated network-none clone. **There is no primary apply command/function.**
It neither migrates nor quarantines the primary, publishes/acknowledges an
outbox effect, releases a lease, resets a cursor, starts a consumer, or changes
readiness. UI, venues, Redis and paid providers are outside its scope.

## Preconditions and bounded invocation

After code review, an operator needs a fresh root backup, matching legacy
recovery and signed inspection receipts/expectation, and a fresh signed accepted
quarantine clone rehearsal bound to those same bytes. Evidence older than two
hours is rejected; old receipts remain historical evidence, not current authority.
The primary database must already be running and all application services/clients
must remain stopped. The exact existing Redis infrastructure is tolerated but
never contacted. No service is automatically stopped or started.

```powershell
python scripts/paper_runtime_schema_upgrade.py `
  --manifest-path <fresh-backup-manifest> `
  --recovery-receipt-path <matching-legacy-recovery-receipt> `
  --legacy-inspection-receipt-path <signed-inspection-receipt> `
  --legacy-inspection-signature-path <inspection-detached-signature> `
  --expectation-path <exact-legacy-row-expectation> `
  --clone-receipt-path <accepted-fresh-quarantine-clone-receipt> `
  --clone-signature-path <clone-detached-signature> `
  --confirmation READ_ONLY_PAPER_TARGET_ROLE_AND_RESTORE_BINDING
```

The only primary credential is the existing fixed
`D:/Kairos/runtime/paper-gate/secrets/persistence_database_url`, mounted read-only
inside the reviewed immutable runner. The host never reads its value. The worker
rejects any other role/host/port/database or DSN options, rewrites only the fixed
target to its shared database namespace's numeric loopback, and opens a
`default_transaction_read_only=on`, repeatable-read/read-only transaction.
No runtime data volume is mounted into the worker or clone.

The accepted runner is the catalog-pinned `kairos-persistence@1ca8bf38...` image
digest, not current HEAD, a tag or another shadow runner. Package inventory,
migration hashes, repository primitive hash and snapshot worker bytes are checked.

## What a passing receipt proves

- Actual `kairos` role/session, schema CREATE/USAGE, UUID EXECUTE, SELECT/UPDATE
  capabilities, relevant ownership and no row-security masking. No test DDL is
  executed; inspection of privileges is not an attempted primary migration.
- Full SHA-256 digests/counts of all legacy public base tables, including seven
  bootstrap/Timescale tables and original `schema_migrations` rows; all public
  sequence states and `public_execution_events.event_seq` maximum.
- Exact accepted legacy bootstrapped schema, manifest checkpoints, fresh backup
  bytes, and identical restored history. Primary identity/history/role snapshots
  must remain unchanged before and after the clone proof.
- Streamed client hashing with sixteen-row prefetch, length-prefixed UTF-8
  framing, PostgreSQL C-collation ordering and 8 MiB work_mem. Fixed bounds:
  4 MiB per row, 1 GiB total row bytes, two million total rows, 300 seconds per
  snapshot, 120-second statements and 5-second lock timeout; backup <=256 MiB.
  The disposable clone is limited to one CPU, 3 GiB memory, 256 processes,
  2 GiB data tmpfs and a separate 128 MiB temporary tmpfs; no host data volumes,
  bind mounts or published ports are added. Its pinned PostgreSQL/TimescaleDB
  command explicitly fixes `shared_buffers=64MB`, `work_mem=4MB`,
  `max_connections=20`, `max_worker_processes=8` and
  `timescaledb.max_background_workers=4`. The snapshot's transaction-local
  8 MiB work_mem remains unchanged. Restore keeps its 300-second timeout and
  source background-job owners remain constrained clone-local NOLOGIN roles.
  The former 1 GiB data tmpfs exhausted its hard capacity during a read-only
  clone restore; compressed archive bytes do not bound restored data/index/WAL
  bytes. A resource failure still rejects the proof and cleans up the clone:
  there is no automatic retry, volume fallback or further resource expansion.
- A new detached-GPG-signed read-only receipt beside the protected backup;
  existing receipts/archives are not overwritten. Raw rows, lease ownership,
  client details and credentials do not enter stdout or the receipt.

Tests in this slice are hermetic. A test pass is **not** a real preflight receipt;
the reviewed command must still be run by the separately authorized operator.

## Next gate remains separate

An accepted read-only receipt still leaves `consumer_restart_permitted=false`.
The historical `141879` pending outbox facts cannot be inferred published or
unpublished at the transport boundary, and exact quarantine is not a queue drain.

A future separately reviewed proof would have to bind one atomic primary
transaction: exact runtime migrations `001–016,018` (never `017/sim_*`) and one
`quarantine_expired_outbox_exact` call for the previously signed identity. It must
prove same-connection/savepoint behavior, rollback of both operations, all-history
preservation except the explicitly allowed one-row quarantine metadata, immutable
publish attempts/payload/ACK facts, response-loss handling by read-only inspection,
backup-after, and an identical runtime17-specific clone restore. It requires
separate acceptance before implementation/apply; this controller has no such path.

Do not weaken `Test-Recovery.ps1 -RuntimePreflight`, which intentionally certifies
only legacy `001–012`. No subscriber/dispatcher restart, replay, bulk ACK, cursor
reset, real order or readiness promotion follows from either receipt.
