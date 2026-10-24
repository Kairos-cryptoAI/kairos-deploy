# Current-source non-trading runtime

The explicit `scripts/runtime_epoch_current.py` launcher uses the existing
native epoch controller and accepted original history seed. It creates a new
owner, database, Redis, network and resource names. It neither adopts a stopped
historical owner nor enables the Execution LIVE service. Old default controller
profiles, frozen research locks, receipts, queues and fingerprints remain
historical evidence, not inputs to a silent upgrade.

## Admission and native work

Plan-only is the default. An execute call requires one exact public profile:
`kairos.current-nontrading-profile.v1`, current Deploy/Core/Persistence/Quant
commit IDs, independently pinned runner recipe commit, runner receipt path/digest, wheelhouse/manifest digest and a
collision-checked private IPv4 `/28`. No secret or approval boolean is part of
that public profile. The launcher verifies clean signed main/origin identities,
the Meta current-release gate, exact runner source/recipe/runtime/migrations,
local image ID/user/labels, and wheel payloads against signed Git archive bytes.
The image recipe may be a separately GPG-verified ancestor of current Deploy
only when the exact Git blob bytes and modes of `.dockerignore`,
`docker/Dockerfile` and `docker/entrypoint.sh` are unchanged. Its workflow and
receipt still identify that exact immutable recipe commit; the current
orchestrator/source identity is not replaced by the image recipe identity.
The downloaded build artifact must independently be obtained from the exact
successful reviewed GitHub workflow; a local JSON receipt alone is not remote
build attestation.
The profile also pins the imported immutable `worker_image_id`. Classic Docker
can use the receipt's config ID; this computer's containerd image store uses
the exact archive OCI manifest digest instead. Admission permits only these
explicitly linked identities, never a mutable tag or unrelated digest. The
unchanged build receipt continues to distinguish config, archive manifest and
registry manifest; none is relabeled as another.

The original `2408db…` dump and its native verification receipt remain pinned.
Only verified candle history is imported into a new target. Source verification
still uses the historical 18-migration profile; the new target alone uses the
explicit immutable `current-controlled-v1` profile (19 controlled migrations,
33 public tables, including `news_processing`). Historical receipt schemas and
measured table counts are not rewritten to claim that profile. Existing row,
catch-up batch, resource, request and time bounds remain unchanged.

The existing native path owns preparation, seed verification, data-only bounded
catch-up, backup, separate restore/row-table-sequence verification,
`pg_amcheck`, non-trading Redis publication/inbox qualification, serving and its
drained restart rehearsal. Every new worker receipt identifies the selected
schema profile. Any failed/unknown operation remains retained evidence; it is
not an excuse to delete resources or launch a replacement blindly.

## Exact-owner boot and Windows binding

`runtime_epoch_current_boot.py` requires a successful current-runtime receipt,
its independently supplied SHA-256 and a detached signature from the pinned
existing receipt signer. It checks unchanged sources, snapshots, wheels,
images, owner credentials, exact resource IDs/limits/mounts and topology.
Already-running admission is read-only and requires a fresh, drained native
status. Partial or unknown topology, a failed owner, changed fingerprints or an
unresolved prior boot latch refuse automatic action.

For an entirely stopped admitted owner only, boot creates an immutable attempt
latch, starts only that owner's PostgreSQL/Redis, takes and independently
restores a backup before data-only catch-up, proves the old audit prefix and
queue unchanged, verifies a second backup/restore and native Redis state, then
starts the existing owner-bound serve container and requires advanced fresh
status. Its two uniquely named restore clones are retained stopped. Failure
cleanup may stop only exact recorded, still-verified owned IDs; failed creation
or name collision never authorizes stopping the colliding resource.

CURRENT restart and boot polling tolerate only explicitly recognized, fresh,
owner/profile-matching `CATCHING_UP_NONTRADING` and `WAITING_SOURCE_NONTRADING`
startup observations within their existing finite deadlines. These are never
healthy evidence. Success still requires native `RUNNING_NONTRADING`, zero
pending/unresolved/uncompleted messages and natural progress of all five
watermarks. Unknown, failed, stale, foreign or trading-enabled states refuse.
The historical controller's restart behavior is unchanged.

`Install-CurrentRuntimeBootTask.ps1` is also plan-only unless `-Execute` is
supplied. It installs only after read-only admission proves the new owner is
healthy. It creates a new exact-owner task and create-only public binding,
never changes older tasks, and never starts a task during installation. The
interactive exact-owner logon action is hidden `pythonw -I -B`; its inline
bootstrap verifies the binding digest, interpreter and complete sibling Python
source hash inventory before importing workspace code. Logon has a two-minute
Docker Desktop readiness delay, IgnoreNew, no automatic retries and no catch-up
task trigger. Actual OS reboot acceptance is separate from an owned-container
stop/start rehearsal; neither can be claimed from static tests or installation.
A failed task registration retains its create-only binding and refuses another
installation until the exact partial state is reviewed. The inline interpreter
hash check occurs after the interpreter starts; it is not a pre-execution code
integrity boundary for that interpreter.
Installation requires Windows elevation and the exact-owner task uses Highest
for complete read-only CIM process identity. A limited token cannot identify
other elevated Python/PowerShell processes on this host, so the unchanged
no-duplicate guard correctly refuses it. This does not broaden the controller's
signed-source, exact-owner or no-trading resource allowlists.
The scheduled bootstrap additionally requires the exact signed full-host pass
report for its owner, receipt and source revision, and no retained host failure
latch. Installation alone cannot activate this gate; a partial/failed acceptance
leaves the task inert even if registration already happened. All preservation
checks precede task installation; completion is signed only after read-back.
Each acceptance attempt has a create-only UUID directory; a failed attempt is
retained, never overwritten. The gate pins the exact report path in the task
binding and verifies its owner, native receipt, source revision and trusted
signature. Release verification uses this computer's explicitly provisioned
PowerShell executable: elevated Windows does not inherit Codex's bundled PATH.
Its child environment also pins the public GPG verifier and minimal `.EXE`
command resolution; no credentials or general user environment are inherited.
The machine/user PATH and execution policies are not changed.

## Claim limits

A successful isolated data runtime is not the full production trading service,
source-producer qualification, EVEDEX signing/account acceptance, alpha or LIVE
arming. Only the existing public Binance candle capture and non-trading local
delivery run here; no paid model/feed call, exchange credential, strategy, order
or wallet operation is enabled. All readiness remains false / `REJECT_ALL`.
Unknown historical failure causes remain unknown; current safe reason codes do
not retroactively diagnose an unretained sample.
