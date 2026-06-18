# kairos-deploy

Deployment & orchestration for the **Kairos** AI futures trader: one `docker compose`
stack that wires every layer together with Redis (message bus), TimescaleDB (history),
and Prometheus + Grafana (monitoring).

## Layout
All Kairos repos are checked out as **siblings** under one parent directory:
```
parent/
  kairos-core/  kairos-llm/  kairos-quant-scouts/  kairos-text-scouts/
  kairos-router/  kairos-aggregator/  kairos-macro-strategist/
  kairos-risk-manager/  kairos-execution-engine/  kairos-deploy/
```

## Quick start
```bash
# from the parent directory
cd kairos-deploy
make clone                # grab all sibling repos (or clone them yourself)
cp .env.example .env      # fill in KAIROS_OPENAI_API_KEY etc.  (DRY_RUN stays true!)
make build && make up
make logs
```

## Services
| container | layer | image/build |
| --- | --- | --- |
| redis | message bus (Redis Streams) | redis:7 |
| timescaledb | history / audit (`timescaledb/schema.sql`) | timescale pg16 |
| quant-scouts | 1A | built from `kairos-quant-scouts` |
| text-scouts | 1B | built from `kairos-text-scouts` |
| router | 2 | built from `kairos-router` |
| aggregator | 3 | built from `kairos-aggregator` |
| macro-strategist | 4 | built from `kairos-macro-strategist` |
| risk-manager | 5 | built from `kairos-risk-manager` |
| execution-engine | 6 | built from `kairos-execution-engine` |
| prometheus / grafana | monitoring | upstream |

## Safety
`KAIROS_DRY_RUN=true` by default — the execution engine will not send real orders until you
explicitly flip it. The minimal infra footprint matches the spec's ~$100/mo budget
(8 vCPU / 16-32 GB VPS + residential proxies for the Text Scouts).

---
Part of the [Kairos](https://github.com/Kairos-cryptoAI/kairos) system. MIT licensed.
