# Dedicated BuildKit resource/cancellation qualification

This opt-in engineering controller does not change the default builder, Docker
context, existing Compose files, source locks, shared BuildKit caches or services.
Its default is `PLAN_ONLY_NO_NATIVE_CALLS`. No prior Docker gate receipt is
reinterpreted: prior `BUILD_RESOURCE_AND_SERVER_CANCELLATION_UNPROVEN` remains
historical evidence. A new synthetic receipt is not production build qualification,
runtime recovery proof, strategy evidence or trading authority.

## Dependency and isolation

The candidate is pinned to the official `moby/buildkit:v0.32.2-rootless`
Linux/amd64 manifest digest
`sha256:60d1f642e29dc938bd6c109ba5500849fccf41921927c5339788b8227f57feb9`.
Official Hub metadata maps it from the release's multi-platform index
`sha256:504731e577c20559c00f968f33219f30115e70be29ab96728d1d06e963fc494b`.
This matches the release of the locally observed rootful v0.32.2 image; it is a
separate dependency, not permission to substitute the rootful/default builder.
Local exact image presence and independently verified Docker image ID are
required before a reviewed native attempt. The controller never pulls images.

The only instance is a fresh UUID-labelled rootless server: network `none`, no
ports, host mounts/socket, devices or privileged mode; read-only root filesystem;
1 CPU, 1 GiB RAM, zero swap, 128 PIDs; disposable tmpfs data 512 MiB/tmp 128 MiB plus
two 16 MiB runtime directories. Rootless OCI uses the native snapshotter, parallelism
one and **process sandbox enabled**. The three explicitly reviewed rootless
exceptions are seccomp/AppArmor/systempaths unconfined.
Docker inspect must expose exactly the seccomp/AppArmor options and empty
`MaskedPaths`/`ReadonlyPaths` for the consumed systempaths operand; omitted,
nonempty or additional security settings are rejected. The create argv still
contains all three reviewed exceptions, not a relaxed inspector wildcard.
Any platform which requires
privileged operation, no-process-sandbox, extra devices, sysctl changes or relaxed
resource caps is rejected; no automatic fallback occurs.

Official interfaces: [rootless v0.32.2](https://github.com/moby/buildkit/blob/v0.32.2/docs/rootless.md),
[daemon configuration](https://github.com/moby/buildkit/blob/v0.32.2/docs/buildkitd.toml.md),
[built-in Dockerfile frontend](https://github.com/moby/buildkit/tree/v0.32.2#exploring-dockerfiles),
[Docker container resource limits](https://docs.docker.com/engine/containers/resource_constraints/).
The rootless documentation warns against no-process-sandbox because ExecOp
descendants may not terminate; that shortcut is intentionally excluded here.

## Proof and fail-closed handling

All inputs are synthetic and generated inside the owned server. Its own public
BusyBox/musl files are copied into a tiny scratch context; no registry/base image,
Dockerfile frontend, provider, credentials or host project data is fetched. A
fixed Dockerfile `COPY --chmod=0555` gives the public BusyBox executable and musl
loader read/execute permission; `COPY --chmod=0444` keeps the synthetic payload
read-only. An empty public scratch skeleton is copied first with explicit
`0755` directory modes. This is required because numeric COPY chmod also sets
automatically created destination parents in this exact BuildKit release; a
file-only `0555` COPY must not create read-only `/bin` or `/lib` parents. The
skeleton contains no binaries, scripts, secrets or private cache data.
These modes do not depend on the context's restrictive umask, and do
not relax the server's caps, rootless identity or process sandbox. Earlier
permission-denied receipts remain failed evidence; only a new reviewed native
attempt can qualify this corrected synthetic fixture. A
COPY-only rootfs is exported before any ExecOp and its five fixed public paths
are inspected numerically (modes and UID/GID, rejecting symlinks and extra
output). Both exports must prove `0755` parents and the fixed read-only file
modes. Between these real measurements only the public binary-source context's
`bin` and `lib` directories are changed from the restrictive creation mode to
`0755`; the explicit destination skeleton is unchanged. The server's private
roots retain `0700`. This records new before/after facts, not reconstructed
permissions for any old failed local export. The 96e5/v4 attempt failed at the
local receiver before either numeric probe; it remains failed with no recorded
rootfs modes. An unsuccessful ExecOp still fails the gate.
The source-bound mount-only observation on Deploy2417ad
(`run-0e49d3931c3a414f8d6a2decf2f5e79c`) proved effective `noexec` on
all eight fixed mount rows in the container and daemon namespaces, including the
private native-snapshot backing data. It executed no build and did not qualify
server resources or production builds. Its positive cleanup and old failed
ExecOp receipts remain distinct evidence, never rewritten.

Only `/home/user/.local/share/buildkit` now requests explicit `exec` while
retaining `nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700`. This is the
private owned snapshot backing tmpfs, not a host mount, shared cache, root mount
or process-sandbox exception. Other three requested tmpfs options are unchanged.
Before any fixture/build and after the fresh post-cancellation build, a fixed
read-only proc projection must independently prove exact effective tmpfs flags:
the data path is executable; the other three paths remain `noexec`; all eight
rows are rw/nosuid/nodev and directory mode0700 UID/GID1000. Daemon PID/start ticks
and mount namespace are stable inside each projection; both complete projections
must match across the synthetic campaign. Missing/duplicate selectors, PID reuse,
incorrect required flags or identity drift fail closed. Only comm/stat/mountinfo and numeric
stat for the fixed paths are read; no raw argv, environment, private cache file
or mount-table contents are emitted. The single probe is limited to8KiB output,
5s operation plus the existing4s CLI tree proof inside the unchanged160/20/180s
budgets. This measurement cannot substitute for real ExecOp/fault/cancellation.

Until a new reviewed full synthetic attempt actually passes, the explicit exec
correction remains unqualified; chmod, COPY-only exports and requested Docker
options are not accepted execution proof.
A deterministic tiny build must match the fixed payload hash. A separate exit37
fault must produce its specific marker and exit37 failure, not merely any CLI
error. A real two-process spin ExecOp is then observed by PID+start ticks,
namespace and bounded cgroup ancestry as viewed by the server observer. OCI
creates a distinct child cgroup namespace; its inode is recorded, not wrongly
equated to the daemon inode. Exact old PID/start identities must disappear as
well as argv markers. Kernel `cpu.max`, `memory.max`,
`memory.swap.max`, `pids.max` must independently match Docker HostConfig; actual
throttling must increase under spin load.

The exact client PID/start-tick pair and fixed build arguments are checked before
it is terminated **inside the Linux server**, not by a Windows timeout.
Acceptance requires all marked server workers gone, acknowledged nonzero client
exit, daemon still alive and a fresh uncached successful build after cancellation.
Finally the exact owned server must stop with PID zero, be removed, and unrelated
container/network/volume/image inventories must match the original snapshot. Concurrent
unrelated resource changes fail the proof; they are not cleaned up by this tool.

Create-only intent/ack/receipt files, exclusive workspace creation, an exclusive
lease and exact reviewed source binding prevent duplicate launches or silent
replacement. A workspace collision cannot append a receipt to the old workspace.
The optional `--invocation-owner` is an exact lowercase UUID4 generated by the
reviewed outer watchdog before launching this attempt. It binds subsequent
fallback cleanup to that invocation; it never adopts an existing lease or run.
Without it the controller generates a fresh UUID4. Invalid IDs are refused
before any path/lease/native operation; the fixed exclusive lease still applies.
An unknown creation, lost server cleanup or changed ownership retains its lease.
Failure evidence is always retained; a failed work phase may release the lease
only after exact positive owned cleanup and unchanged inventories are proved.
The tool never automatically retries or prunes. Windows CLI
descendants use the previously reviewed hash-bound suspend/assign/resume JobObject
helper (fixed SHA 601d8c07…); this CLI containment is recorded separately and is
**not** accepted as Linux BuildKit CPU/cancellation proof. Work deadline 160s and
shared cleanup deadline 20s are inside a 180s native window; a reviewed outer Windows
launcher must additionally enforce the whole controller process lifetime and
independent cleanup handling before native execution is authorized.

## Operation boundary

Offline contracts: `python -m unittest tests.test_buildkit_resource_gate`.
Plan: `python scripts/buildkit_resource_gate.py` (no files/native calls).
An explicit native switch also requires fixed confirmation, complete reviewed
controller/deploy hashes and exact pre-existing image identity; root must review
its launcher, image acquisition and single attempt first. Do not invoke it as a
normal CI dependency or grant an inherited/shared builder workload to it.

Until an actual accepted new receipt exists, server qualification is `UNPROVEN`.
Even an accepted synthetic proof leaves `production_build_qualified=false`,
`PAPER_QUALIFIED=false`, `ALPHA_READY=false`, `LIVE_READY=false` and
`STRATEGY_POLICY=REJECT_ALL`. Qualification of real repository builds needs a
separate reviewed integration with this resource/cancellation boundary.
