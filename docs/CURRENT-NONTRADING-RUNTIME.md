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
commit IDs, runner receipt path/digest, wheelhouse/manifest digest and a
collision-checked private IPv4 `/28`. No secret or approval boolean is part of
that public profile. The launcher verifies clean signed main/origin identities,
the Meta current-release gate, exact runner source/recipe/runtime/migrations,
local image ID/user/labels, and wheel payloads against signed Git archive bytes.
The downloaded build artifact must independently be obtained from the exact
successful reviewed GitHub workflow; a local JSON receipt alone is not remote
build attestation.

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

`Install-CurrentRuntimeBootTask.ps1` is also plan-only unless `-Execute` is
supplied. It installs only after read-only admission proves the new owner is
healthy. It creates a new exact-owner task and create-only public binding,
never changes older tasks, and never starts a task during installation. The
interactive limited-user logon action is hidden `pythonw -I -B`; its inline
bootstrap verifies the binding digest, interpreter and complete sibling Python
source hash inventory before importing workspace code. Logon has a two-minute
Docker Desktop readiness delay, IgnoreNew, no automatic retries and no catch-up
task trigger. Actual OS reboot acceptance is separate from an owned-container
stop/start rehearsal; neither can be claimed from static tests or installation.
A failed task registration retains its create-only binding and refuses another
installation until the exact partial state is reviewed. The inline interpreter
hash check occurs after the interpreter starts; it is not a pre-execution code
integrity boundary for that interpreter.

## Claim limits

A successful isolated data runtime is not the full production trading service,
source-producer qualification, EVEDEX signing/account acceptance, alpha or LIVE
arming. Only the existing public Binance candle capture and non-trading local
delivery run here; no paid model/feed call, exchange credential, strategy, order
or wallet operation is enabled. All readiness remains false / `REJECT_ALL`.
Unknown historical failure causes remain unknown; current safe reason codes do
not retroactively diagnose an unretained sample.
