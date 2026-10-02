# Atomic runtime17 / exact-row clone proof

This is a separate, opt-in recovery gate. It has **no primary write path** and
does not permit a consumer restart, PUB/Redis call, retry, ACK/cursor reset, order,
PAPER qualification, or readiness promotion. Primary must remain STOPPED.

## Offline admission

`paper_runtime_atomic_clone_rehearsal.py` defaults to preparing a plan only.
It reuses the unchanged legacy evidence reader, detached-signature verification,
accepted clone verifier and native read-only snapshot contract. Every backup,
inspection, recovery, clone and read-only receipt must remain fresh (at most two
hours; no future dates), with exact hash/signature/backup bindings. Freshness is
checked again before each worker, before COMMIT, and before a PASS receipt.
Expired evidence needs a separately authorized fresh proof; no expiry override
or automatic resource/operation retry exists.

The exact accepted OCI runner and persistence revision come from the old catalog:
`sha256:2e10e9e936eae3a4a411f65d8b0bd14670ba808368eeff94b4e24021aa291077`,
`1ca8bf38d265ece7a95f749a268075549f80c043`. The worker verifies installed
repository/database module bytes, every migration hash and exact inventory.
Only `001–016,018` applies. Never `017`, latest runtime, or operator migration026.

## Atomic core and history policy

One physical connection owns a repeatable-read outer transaction and bounded
schema/table locks. The adapter lets unchanged `Database.migrate()` and exact
quarantine acquire the same connection and enter nested savepoints. Backend PID,
outer transaction activity, two acquisitions/savepoints, and one quarantine call
are checked. Rejection or failure rolls back the **whole** upgrade.

The signed identity must name row117625 with its exact producer/message/topic,
payload hash, publish attempts, lease identity and reconciliation ID. Only its
lease owner/until, canonical last_error and four migration018 metadata fields
may change. Every other outbox row preserves all old fields and receives exactly
the new NONE/NULL defaults. The projection restores old metadata **only** for
row117625; it never masks lease/error fields on the rest of the table.

All27 legacy tables are compared by complete framed row digests, not counts alone.
Old12 migration rows/timestamps, all old sequence states, payload/ACK facts and
public-event watermark are preserved. Exactly five migration markers and eight
new runtime tables are permitted; only the new UUID identity table starts with
one row. Postcommit dump/restore must reproduce all35 runtime tables exactly.

## Native execution needs separate code/resource review

Only an explicitly reviewed invocation adds `--native-clone-only`. A controller
owns one random, labelled, `network=none` clone at a time: 3GiB RAM, 2GiB data
tmpfs,1CPU; its readonly filesystem worker has512MiB RAM,1CPU, no capabilities,
no new privileges and only the clone loopback DB route. Images must exist locally
(`--pull=never`). No primary secrets are mounted. The second restore DB starts
only after the first clone is removed. Runtime work is bounded by300s, with a
separate at-most10s identity-validated failure cleanup; no limit enlargement.

Native rollback checkpoints occur after each suffix migration's real marker
insert, after all migrations, after quarantine, and before COMMIT. The same
legacy clone is reused only after an acknowledged rollback and complete27-table
baseline comparison. The last attempt injects response loss **after real COMMIT**,
then resolves it using a fresh read-only connection. It does not rerun quarantine.
The mixed-state negative case modifies only in-memory metadata, never DB rows;
it checks INDETERMINATE classification, not a real mixed-state DB experiment.

Before any COMMIT, an exclusive bounded precommit intent is flush/fsync/readback
acknowledged in a **permanent host-backed** attempt subdirectory below backups,
mounted at `/evidence`; it is not worker or database tmpfs. An intent write failure
prevents COMMIT. Host-bind fsync is not a claim of power-loss durability across
the Windows/Docker/storage stack. Plans, every intent and partial after-dump are
never deleted on native failure. A redacted create-only failure receipt records
observed versus NOT_OBSERVED states and retained paths; no failure grants apply
authority. Old input staging may be cleaned independently.

The native receipt explicitly states
`primary_history_observed_during_rehearsal=false`: stopped primary container,
volume and network metadata are bound before/after without starting or reading
its DB. Historical clone binding comes from the accepted signed full27 baseline
and exact source backup. This is not a fresh current-primary SQL proof.

`validate_paper_runtime_atomic_receipt.py --receipt ... --plan ...` independently
checks the native receipt, retained plan/intent/backup-after, source metadata,
source/code/resource identity and exact runtime restore digest. Optional
`--signature ...` verifies the existing trusted signer. Unsigned native receipts
remain unsigned; neither signed nor unsigned receipts authorize primary apply.
Protecting primary quarantine requires a separate acceptance/review.

## Offline tests are not native proof

Run `python -m unittest discover -s tests -p 'test_paper_runtime_atomic_*.py' -v`.
Synthetic/fake orchestration receipts are labelled `PASS_OFFLINE_MODEL_ONLY` and
`actual_postgres_rollback_proven=false`. Only a completed authorized native clone
run can emit `PASS_NATIVE_ATOMIC_CLONE_ONLY`. No fake savepoint model proves
actual PostgreSQL DDL rollback. The frozen catalog/controllers/old receipts and
legacy `Test-Recovery.ps1 -RuntimePreflight` remain unchanged.

## Observed bounded native attempt: incomplete (2026-10-02)

The reviewed root invocation exhausted the total300s bound. Its retained
`backups/paper-runtime-atomic-attempt-2d7226ae315b/failure-9215691996ce.json`
records `FAILED_NATIVE_CLONE_NO_AUTHORIZATION` at `2026-10-02T21:05:18.711334Z`,
phase `after_migration_016`, error category `TimeoutExpired`. The failure receipt
SHA256 is `5d85fde977ab22718629f852bb082ffe0911d122121a4d6bc816a9ab8f0f0289`.

Observed: the restored legacy clone matched the accepted all27 baseline; native
rollback checkpoints after migration013,014 and015 completed and each matched
the full legacy baseline. Migration016's checkpoint was started, **not accepted**.
Migration018, quarantine, before-COMMIT, lost-COMMIT-response resolution and
postcommit runtime35 dump/second restore were not proved by this attempt.
`commit_outcome=NOT_OBSERVED`, `runtime_restore_verified=false`. No PASS receipt
was produced; the offline model suite does not replace these missing proofs.

Permanent host artifacts retained: `atomic-plan.json`, the failure receipt and
the empty `atomic-intents` directory. No precommit intent or after-dump had yet
been produced. The post-run metadata-only check of the exact owned scope
`com.kairos.scope=paper-runtime-atomic-clone-proof` returned zero containers; no
cleanup failure receipt was present. No stop/start or retry was performed by the
implementing agent. The source remained outside the write API: failure metadata
records `primary_mutations=0`, no current-primary DB history observation, no
primary apply/quarantine authorization, no consumer restart or readiness change.

This release therefore contains the implementation and partial bounded native
evidence, **not a completed atomic runtime/quarantine/restore gate**. No automatic
retry or resource-bound expansion follows. Further native work needs a separate
reviewed authorization and fresh evidence as necessary; protected primary
quarantine still requires independently accepted complete proof.
