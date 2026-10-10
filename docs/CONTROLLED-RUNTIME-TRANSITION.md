# Controlled runtime transition

This additive protocol upgrades only the stopped legacy database after a
current-source isolated rehearsal is accepted. It does not authorize trading,
activate a consumer, dispatch an outbox item, reset a cursor, or replay an
unknown publication. Historical recovery workers, source locks and receipts
remain unchanged.

## Admission and source provenance

- Core, Persistence and Deploy must be clean signed `main` revisions matching
  their local `origin/main`; relevant hosted CI must pass before native work.
- `prepare_controlled_runtime_wheels.py --prepare` builds Core/Persistence from
  signed Git archives using an offline, pinned Hatchling backend. Every runtime
  wheel file must match its signed source bytes; generated runtime files fail.
- The controller extracts the signed Deploy scripts into a private immutable
  snapshot and verifies that snapshot around every worker invocation. Workers
  receive read-only scripts/wheels and a separate private writable output.
- Each run has a create-only owner lease, bounded private captures, exact Docker
  identities, resource limits and assign-before-resume Windows supervision.
  Existing live owners and failed historical leases are never adopted.

## Required sequence

1. Run the clone controller through its hidden `--supervise` path with the exact
   Deploy revision, wheelhouse and clone-only confirmation. It takes a new
   official backup of a read-only physical copy and independently restores the
   complete legacy history twice before testing the current profile.
2. The current worker rehearses migrations `001`–`016`, `018`, `026` and exact
   expired-outbox quarantine in one physical transaction. Nine injected faults
   must roll back every legacy row, sequence and schema change. An intentionally
   lost COMMIT reply must be classified through a fresh read-only connection,
   never by retrying the mutation. Current-profile idempotence, least-privilege
   runtime access and negative permission controls must pass.
3. A separate empty disposable database and Redis fixture prove durable inbox
   completion before ACK, duplicate-handler isolation, unknown-publication
   quarantine and exact positive-evidence DB-only resolution. This fixture is
   not evidence that the historical primary Redis queue has been reconciled.
4. Restore the upgraded clone's new backup independently, compare its entire
   history and run whole-database `pg_amcheck`. Verify the original stopped
   primary's file content and observed metadata are unchanged; clean all owned
   containers and verify the Windows child process tree is empty.
5. Accept and detach-sign both the clone and hidden-supervisor receipts. Only
   `PASS_CURRENT_CONTROLLED_CLONE` with exact bound artifacts can admit the
   primary controller. Keep original backups and private diagnostics local.
6. After separate owner approval, invoke the primary controller with
   `--execute-primary`, the signed clone/supervisor directories, exact revision,
   wheelhouse and primary-only confirmation. The default is always plan-only.
   The hidden supervisor bounds the operation and stops the exact original
   PostgreSQL container afterward, including an interrupted child.

The primary transition creates a run-unique temporary login, grants only the
reviewed migration-role assumption, atomically migrates/quarantines the exact
reviewed expired row, and verifies the new runtime login's positive/negative
permissions. It then drops its temporary login, makes a backup after, restores
that archive into an isolated cluster and checks all histories and supported
heaps/B-trees. Restored-cluster verification deliberately makes no claim about
omitted role globals or original runtime ACLs.

## Historical Redis evidence and remaining runtime work

`cold_redis_acceptance.py` is a separate read-only investigation. It never
starts or contacts the original Redis server or reads its credential values.
It observes an owned copy of the stopped Redis volume and accepts only exact
positive, complete stream evidence. A missing record is inconclusive, not
permission to republish. A conflict, truncation, incomplete scan or changed
source fails closed. The resolver itself performs a DB-only acknowledgement;
it never sends a Redis command.

`PASS_PRIMARY_SCHEMA_QUARANTINE_ONLY` closes only the controlled schema and
quarantine transition. It does **not** close historical backlog reconciliation,
fresh market catch-up, consumer activation, external delivery, strategy/model
qualification, venue qualification, off-host recovery or LIVE readiness.
All trading and paid-provider authority stays off; policy stays `REJECT_ALL`.

Never promote a failure receipt, delete partial evidence, relax a fingerprint,
claim an uncertain COMMIT did not happen, or reset leases to make a test pass.
