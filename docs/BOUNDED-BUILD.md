# Bounded Compose build adapter

## Scope and current acceptance

`scripts/bounded_build.py` is an opt-in **synthetic-only** adapter. Default
invocation emits `PLAN_ONLY_DEFAULT_DENY` without native calls or files. There
is no argument accepting a repository context, arbitrary Compose file, target,
Dockerfile, provider, endpoint or build flag. Ordinary nine-image and six-image
PAPER builds and their existing workflows remain unchanged and **not qualified
by this adapter**. No PAPER services are started.

The underlying rootless resource controller at Deploy
`f0ddd005df20b15e01f70023a6effaf17c0f61be` has a separately accepted
`PASS_SYNTHETIC_ONLY` receipt in
`D:/Kairos/runtime/buildkit-resource-20261003/run-b0feb0e12b3d4d0abcbecc2bf2055c03/receipt.json`.
That observed CPU throttling, two real ExecOp processes disappearing after
client cancellation, a fresh successful build, and owned cleanup. It is **not
a Compose adapter run**. This new adapter remains unqualified until its own
reviewed native fixture produces a receipt; offline tests cannot change that.

## Boundary

The adapter explicitly creates one fresh nonprivileged, rootless official
`moby/buildkit@sha256:60d1f642e29dc938bd6c109ba5500849fccf41921927c5339788b8227f57feb9`
server, using the existing strict full-container inspector. No image pull is
permitted. CPU is one core, memory 1 GiB, additional swap zero, PID limit 128,
and daemon ExecOp concurrency one. Writable state is only invocation-owned
tmpfs: 512 MiB data, 128 MiB `/tmp`, and two 16 MiB roots. The data root alone
is explicitly executable, UID/GID 1000, mode 0700, nosuid/nodev. Seccomp,
AppArmor and system-path exceptions are the existing reviewed rootless
exceptions; process sandbox remains enabled. There is no privileged container,
host socket, host volume, public port, host PID namespace or external network.

The adapter adds actual bounded `statfs` projections in both container and
daemon namespaces. All eight rows must match the four hard capacities and the
already-verified daemon PID/start/mount-namespace identity. Requested Docker
options or BuildKit GC limits alone are not accepted as hard disk proof.
Capacity and free-space observations are recorded separately: free space can
change during a build; the hard capacity cannot. It does not claim an inode
stress/OOM test or suitability for larger real images.

Buildx uses **remote**, not its `docker-container` driver. The endpoint is only
`docker-container://<exact-owned-server-name>`: the connection helper runs
`docker exec -i ... buildctl dial-stdio`. This is not a mounted Docker socket
or an exposed TCP BuildKit listener. The CLI and connection helper have an
allowlisted environment, fixed local daemon address, dedicated Docker and
Buildx configurations and no inherited home, credentials, proxies or default
builder. Registration omits `--use`, `--append`, automatic bootstrap and daemon
flags; the saved node is independently checked. Empty Buildx store directories
and an empty current selection are legitimate; named/default selections,
extra nodes, flags, files, endpoints or loading policy are rejected.

The only Compose target is `fixture`. Its three generated cases use `FROM
scratch`, two hash-bound public executables from the immutable owned image,
fixed payload and explicit COPY modes. No caller file is copied or mounted.
The entire context is allowlisted before each build, including rejection of
extra `.env`, `.dockerignore`, links and files. Explicit empty env-file and
project paths prevent ambient interpolation. Pull, network, attestations and
SBOM are disabled. Success validates the payload hash inside the actual build;
fault must fail with exit 37; cancellation runs two marked CPU workers.

## Cancellation, deadlines and cleanup

Every Docker/plugin/connection-helper Windows tree is created suspended and
assigned to the existing reviewed kill-on-close Job before resuming. Logs have
a 256 KiB bound. The work deadline is 160 seconds; cleanup is at most 20 seconds
and also ends by the original 180-second deadline. Each CLI reserves up to four
seconds **inside** its phase for zero-active-process proof. A root-reviewed
outer launcher must additionally enforce the whole Python invocation and owned
fallback cleanup before authorizing native execution; this adapter is not
permission to run a bare unguarded process.

Cancellation projects only the owned server's exact `buildctl dial-stdio`
PID/start identities, UID 1000, bounded cgroup ancestry and the server's cgroup
namespace. It validates the entire set before TERM, observes the same set again
and, only for exact unchanged survivors, sends one identity-revalidated KILL.
Both stimuli and their observation share the existing 15-second phase; no
deadline is extended. New/reused PID, changed start, UID, namespace or cgroup
fails closed before the forced signal. It never signals the daemon, ExecOp or
host processes, and never accepts a zombie as disappearance.

The receipt explicitly records `TERM_ONLY` or
`TERM_THEN_FORCED_DISCONNECT`, the numeric proxy identities and forced count.
This is a controlled transport-disconnect fallback, **not proof of graceful
Compose/Solve-client context interruption**; `graceful_compose_context_proven`
remains false. Acceptance still requires nonzero Compose exit, disappearance
of both observed worker and transport PID/start identities, a still-running
daemon, and a fresh successful **Compose** build. Owned-daemon stop during
cleanup does not turn an unproven cancellation into a pass.

The retained attempt
`D:/Kairos/runtime/bounded-build-20261003/run-5ae0d524693c4e6bbf6e1a259dbdd4bb/receipt.json`
failed `LINUX_COMPOSE_CANCELLATION_UNPROVEN`: all 26 post-TERM polls retained
the same two token-bearing ExecOp identities; Compose did not exit until Job
cleanup. Owned cleanup succeeded, but that is not cancellation acceptance.
BuildKit v0.32.2 installs TERM/INT app-context handlers; its `dial-stdio`
proxy action blocks on stream copies without observing that context. Therefore
the old TERM-only stimulus does not establish a closed stream. This reviewed
candidate is still unqualified until one separately authorized native run.

The direct qualifier and adapter share an exclusive create-only lease. Old,
stale or foreign leases are never adopted/deleted automatically. Fresh UUID4
workspaces, intents, acknowledgements and receipts are create-only; collision
cannot append to old evidence. Cleanup verifies the exact server before
stop/remove, removes only the private remote registration and independently
verified tiny synthetic output images, and compares global resource identities
with the baseline. Foreign image tags/consumers, unknown creation outcomes,
changed ownership or unproven Windows/Linux cleanup preserve the lease and
failure evidence. Positive owned cleanup may release the lease after a failed
test; it never removes that test's receipt and never retries automatically.
Public-only baseline resource IDs and the exact Compose version are persisted
before the server-create request, for independent launcher verification rather
than retrospective interpretation of a text log.

The output-image inspector accepts either no repository digest or exactly one
`kairos-bounded-synthetic@<exact inspected Id>` digest. Docker's containerd store
was observed to attach this self-repository digest to its OCI-manifest image Id.
Foreign repositories, different digests, duplicate/additional entries and tags
remain forbidden; the full owner/scope/Compose labels, bounded size and platform
checks are unchanged. The receipt records the observed inspector branch and exact
owned tags/digests only after complete validation. The first actual Compose attempt
failed closed on the earlier empty-digest-only guard; that failed receipt and its
unknown image-cleanup outcome are retained, not reclassified as acceptance.

## Reviewed invocation and follow-on work

Prepare a private `D:/Kairos/runtime/bounded-build-20261003` directory. Root must
review the published source, trusted clean-main identity, existing immutable
image identity and exact SHA-256 of the three fixed Docker/Buildx/Compose
executables before one guarded native run. The adapter requires those hashes,
the published Deploy HEAD, its own source hash, an explicit UUID4 owner, and
`--execute --confirm OWNED_SYNTHETIC_COMPOSE_BUILD_ONLY`. It binds the resource
controller and reviewed Windows Job source and rechecks sources/tools after
the fixture. It never reads a secret to establish these public identities.

Only a resulting `PASS_SYNTHETIC_COMPOSE_ONLY` proves this generated adapter
path on that host/tool/source set. Integration of actual current-source image
builds needs a separately reviewed context/network/dependency allowlist and
proportional resource profile plus its own builds and cancellation evidence;
there is no automatic increase of caps or default-builder fallback. Until then
`production_build_qualified=false`, `PAPER_QUALIFIED=false`, `ALPHA_READY=false`,
`LIVE_READY=false`, and `STRATEGY_POLICY=REJECT_ALL`.

Official references: [remote driver](https://docs.docker.com/build/builders/drivers/remote/),
[Compose explicit builder](https://docs.docker.com/reference/cli/docker/compose/build/),
[rootless BuildKit](https://github.com/moby/buildkit/blob/v0.32.2/docs/rootless.md),
[dial-stdio source](https://github.com/moby/buildkit/blob/v0.32.2/cmd/buildctl/dialstdio.go),
[signal app context](https://github.com/moby/buildkit/blob/v0.32.2/util/appcontext/appcontext.go),
[app-context attachment](https://github.com/moby/buildkit/blob/v0.32.2/cmd/buildctl/common/trace.go),
[docker-container connection helper](https://github.com/moby/buildkit/blob/v0.32.2/client/connhelper/dockercontainer/dockercontainer.go),
[Buildx store](https://github.com/docker/buildx/blob/master/store/store.go), and
[Docker tmpfs](https://docs.docker.com/engine/storage/tmpfs/).
