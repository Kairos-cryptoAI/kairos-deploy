# Native Telegram alert-delivery preparation

The owner selected `KairosCryptoAI_bot`. The final alarm group is `-5155583216`;
all one-shot qualification tests use the separately supplied exact test group
`-100447580288`. The IDs are not inferred or automatically corrected. Token values
never enter source, command arguments, browser, fixtures, receipts or logs.

`scripts/alert_delivery.py` renders native Alertmanager and the actual existing
Prometheus baseline only after exact source-hash and explicit cadence binding.
The committed example is disabled/incomplete. Existing safety rules/scrape job are
unchanged. Browser/TradingView/LLM/trading services are outside this scope.

`docker-compose.alert-delivery.yml` is a distinct `kairos-ops-alerts` project with
only pinned native Alertmanager 0.34.1, read-only operator config/token file binds,
no published host ports, no Docker socket, database or trading mounts, and bounded
128MiB memory/0.25 CPU/pids64/tmpfs. It uses a separate egress bridge and the exact
default source observability network. The PAPER override only changes that network
to `kairos-paper_paper-observability`; it is not applied to business Compose and
does not contact the `kairos-paper-gate` recovery project. A different actual
project/network requires separate identity review. There is no start service/API
in the preparation script. Enabling the generated Prometheus file requires review
of its exact source mount; no business services are implicitly launched.

Native HTTP config fixes the official HTTPS Telegram endpoint, verifies TLS,
disables redirects/environment proxies and renders only status plus fixed safety
label fields. Arbitrary annotations/news/PnL/payloads never reach the receiver.
Egress isolation is not claimed as an endpoint firewall. Alertmanager's bounded
tmpfs is not durable deduplication across process restarts.

## One guarded test and explicit prerequisites

Root imports the token separately. Pre-provision operational root, secrets, token
and receipts with protected explicit operator/Admin/SYSTEM ACLs. In particular,
Python 3.11 Windows `mkdir(mode=0o700)` may create OWNER RIGHTS entries: they are
not silently accepted. Validate metadata and provision the empty receipts folder
before qualification; do not weaken ACL policy.

The explicit `--authorize-one-test` path creates/fsyncs a stable bot/test-chat guard
before API access, verifies bot and chat identities, then fsyncs `SEND_RESERVED`
before a single visibly marked test send. It never retries unknown outcomes or
deletes/reuses a failed journal. Source/message hashes, fixed method counts and
scoped IDs are recorded; group titles/member names and raw transport errors are
not. A successful API response is not human acknowledgment or trading authority.

Prior wrongly supplied-group journals remain untouched. One wrong test-group
attempt reached `SEND_OUTCOME_UNKNOWN`; the owner reported no visible message, but
that does not retroactively prove the API outcome. The corrected exact test-group
qualification stopped before send. The separate read-only diagnostic then returned
HTTP400/API400 `CHAT_NOT_FOUND`, with getMe=1/getChat=1/send=0. The owner must confirm
the bot's membership and exact accessible chat identity. No automatic retry or
new send is authorized by this documentation.

## Evidence versus remaining delivery qualification

Offline unit tests cover durable reservations, repeat guards, message redaction,
type confusion, endpoint restrictions and default Compose JSON normalization.
The exact pinned native amtool accepted the synthetic config and routed all 33
actual base/PAPER rule names to the expected Telegram receiver in network-none
128MiB/0.25CPU containers, with only synthetic token content mounted.

This proves native configuration/routing, not delivery. Actual
Prometheus→Alertmanager→TLS firing/resolved notifications, 503/redaction/restart
behavior, receiver acknowledgment, cadence/escalation and an independent
host-loss watchdog are not operationally qualified. No PAPER/ALPHA/LIVE readiness
flag or reject-all policy changes follow from this slice.
