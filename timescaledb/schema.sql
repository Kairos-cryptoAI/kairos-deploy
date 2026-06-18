-- Kairos time-series storage (TimescaleDB).
-- Stores every message that crosses the bus so the Macro-Strategist can review a
-- week of history and so we can backtest / audit decisions.

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS market_snapshots (
    ts          TIMESTAMPTZ NOT NULL,
    symbol      TEXT        NOT NULL,
    mid_price   DOUBLE PRECISION,
    rsi_14      DOUBLE PRECISION,
    macd_hist   DOUBLE PRECISION,
    ob_imbalance DOUBLE PRECISION,
    funding_rate DOUBLE PRECISION,
    open_interest DOUBLE PRECISION,
    quant_bias  TEXT,
    payload     JSONB
);
SELECT create_hypertable('market_snapshots', 'ts', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS ix_snap_symbol ON market_snapshots (symbol, ts DESC);

CREATE TABLE IF NOT EXISTS sentiment_signals (
    ts        TIMESTAMPTZ NOT NULL,
    topic     TEXT,
    sentiment DOUBLE PRECISION,
    impact    TEXT,
    payload   JSONB
);
SELECT create_hypertable('sentiment_signals', 'ts', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS tactical_commands (
    ts          TIMESTAMPTZ NOT NULL,
    symbol      TEXT,
    status      TEXT,
    reason_code TEXT,
    effort_used TEXT,
    payload     JSONB
);
SELECT create_hypertable('tactical_commands', 'ts', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS strategic_allocations (
    ts                 TIMESTAMPTZ NOT NULL,
    regime             TEXT,
    stable_reserve_pct DOUBLE PRECISION,
    max_gross_leverage DOUBLE PRECISION,
    triggered_by       TEXT,
    payload            JSONB
);
SELECT create_hypertable('strategic_allocations', 'ts', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS executions (
    ts               TIMESTAMPTZ NOT NULL,
    symbol           TEXT,
    side             TEXT,
    status           TEXT,
    filled_qty       DOUBLE PRECISION,
    avg_price        DOUBLE PRECISION,
    fees_usd         DOUBLE PRECISION,
    client_order_id  TEXT,
    exchange_order_id TEXT,
    payload          JSONB
);
SELECT create_hypertable('executions', 'ts', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS equity_curve (
    ts          TIMESTAMPTZ NOT NULL,
    equity_usd  DOUBLE PRECISION,
    daily_pnl_pct DOUBLE PRECISION
);
SELECT create_hypertable('equity_curve', 'ts', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS llm_calls (
    ts        TIMESTAMPTZ NOT NULL,
    layer     TEXT,
    model     TEXT,
    effort    TEXT,
    input_tokens INT,
    cached_input_tokens INT,
    output_tokens INT,
    cost_usd  DOUBLE PRECISION
);
SELECT create_hypertable('llm_calls', 'ts', if_not_exists => TRUE);
