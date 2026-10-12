# Opt-in runtime epoch status monitoring

The optional `docker-compose.runtime-status-monitoring.yml` overlay adds status-file observation to the existing `ops-exporter` and Prometheus path. Base/PAPER source pins were updated to the signed Persistence implementation; their activation and trading behavior are unchanged. The overlay is not part of any default compose invocation and does not start or restart a runtime by itself.

Before an operator uses the overlay, they must provide both required environment values:

- `KAIROS_RUNTIME_EPOCH_STATUS_HOST_PATH`: the exact host path to the intended epoch's `status.json` file (not its parent directory).
- `KAIROS_RUNTIME_EPOCH_STATUS_OWNER`: the exact 32-character lowercase hexadecimal owner for that epoch.

Compose mounts that one file at `/run/kairos-runtime/status.json` inside `ops-exporter`, read-only, with host-path auto-creation disabled. The expected owner and in-container path are passed to the exporter; no credentials or private status diagnostics are exposed as metric labels. The exporter reports fresh `RUNNING_NONTRADING`, stale, `FAILED_CLOSED`, missing, invalid, and unknown-owner states using bounded one-hot gauges.

The overlay selects `monitoring/prometheus.runtime-status.yml`, preserving the existing `kairos-durable-runtime` scrape identity and base alert rules while adding `monitoring/runtime-epoch-alerts.yml`. Alerts distinguish missing status, invalid or wrong-owner status, `FAILED_CLOSED`, stale heartbeat, and absent status metrics. The rules never restart a process or request an epoch retry.

This is configuration, not live qualification. It does not establish that the status file belongs to the intended machine or that its source process is currently running. The owner must be checked against the independently approved epoch record before configuration. A fresh `RUNNING` metric indicates only the exporter’s validated file observation; stale, missing, invalid, or failed-closed states are not healthy.

The exporter source revision pinned by the base deployment must contain the optional status-file metrics before this overlay can observe them. The monitoring configuration cannot backport or enable exporter code. CI validates the overlay's Prometheus config and evaluates synthetic alert fixtures with the repository's pinned, provider-free `promtool` image. Local/native service qualification and deployment are intentionally separate steps.
