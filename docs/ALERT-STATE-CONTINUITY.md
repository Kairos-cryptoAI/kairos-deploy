# Opt-in Alertmanager state continuity

The standalone `docker-compose.alert-delivery.durable.yml` profile is additive.
It is not a default service and does not change historical delivery receipts or
the legacy stateless validator. Its external state volume must be independently
provisioned with the exact policy-bound labels and an accepted local metadata
receipt; the validator does not create a volume or start a notifier.

`scripts/alert_state.py` validates only this explicit durable delta and delegates
all remaining topology, secret-file, endpoint and resource restrictions to the
existing delivery validator. It requires strict `nocopy: true`, a local external
volume, bounded Alertmanager retention and an explicit five-second maintenance
interval. A local Docker volume is neither an off-host backup nor a hard disk
quota. Production remains disabled until real delivery and custody are accepted.

## Separate synthetic engineering proof

`scripts/alert_state_gate.py` is plan-only by default. Its one explicit native
attempt creates fresh, UUID-labelled resources and a synthetic fixture. No
Telegram token, real alert, provider, database, business network, host port or
default Compose service is used. Both processes are limited to 0.25 CPU, 128 MiB
and 64 PIDs, with read-only roots, dropped capabilities and no-new-privileges.
The receiver has network `none`; Alertmanager shares only that owned network
namespace and reaches the receiver over loopback. The volume-init process has
only CHOWN, is network-none, and accepts only a newly empty owned volume.

The fixture exercises one injected 503, one accepted firing notification,
checkpoint persistence, abrupt process death, recreation with the same state,
no duplicate firing in a fixed observation window, one resolved notification,
another checkpointed restart and no duplicate resolved notification. Actual
notification-log hashes, exit 137 and recreated container identities are required.
This proves only **checkpointed local restart continuity** if a native receipt
passes. It does not prove exactly-once delivery, unknown-send/before-checkpoint
crash safety, host-loss recovery, recipient acknowledgment or Telegram delivery.
Alertmanager's [notification log](https://github.com/prometheus/alertmanager/blob/v0.34.1/nflog/nflog.go)
is periodically checkpointed; those distinct windows must not be conflated.

Work is bounded to 120 seconds, cleanup to ten seconds inside the 130-second
window. A separately reviewed outer Windows JobObject launcher must bound the
entire controller, including file operations, and provide independent exact-owned
cleanup. CLI-only timeouts are not accepted as a whole-controller proof. Unknown
creation or cleanup retains evidence and the exclusive lease; nothing is
automatically retried, adopted or pruned. Resources with changed identity are
never removed. Historical failure receipts are immutable.

Before a new native receipt is accepted, qualification remains UNPROVEN.
Even a passing synthetic receipt leaves `telegram_qualified=false`,
`exactly_once_delivery=false`, `host_loss_qualified=false`,
`PAPER_QUALIFIED=false`, `ALPHA_READY=false`, `LIVE_READY=false`, and
`STRATEGY_POLICY=REJECT_ALL`.
