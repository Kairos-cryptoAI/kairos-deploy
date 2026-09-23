import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CockpitApiError,
  COCKPIT_API_PATH,
  MAX_SNAPSHOT_BYTES,
  fetchCockpitSnapshot,
  validateSnapshot,
} from './api.js';

function emptySnapshot(overrides = {}) {
  return {
    schema_version: 'kairos.cockpit.snapshot.v1',
    generated_at: '2026-09-23T00:00:00Z',
    system: {
      runtime_state: 'STOPPED',
      trading_mode: 'DRY_RUN',
      strategy_policy: 'REJECT_ALL',
      readiness: {
        technical_paper_ready: true,
        paper_qualified: false,
        alpha_ready: false,
        live_ready: false,
      },
    },
    markets: [],
    decisions: [],
    lifecycle: [],
    tca: [],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json', ...options.headers },
  });
}

test('accepts a bounded snapshot with the exact v1 contract', () => {
  const snapshot = emptySnapshot();
  assert.equal(validateSnapshot(snapshot), snapshot);
});

test('rejects unknown versions, fields, symbols, unsafe series, and invalid OHLC', () => {
  assert.throws(
    () => validateSnapshot(emptySnapshot({ schema_version: 'kairos.cockpit.snapshot.v2' })),
    (error) => error instanceof CockpitApiError && error.code === 'UNSUPPORTED_VERSION',
  );
  assert.throws(() => validateSnapshot(emptySnapshot({ api_key: 'must-not-appear' })), /unsupported field/);

  const unknownSymbol = emptySnapshot({
    markets: [
      {
        symbol: 'DOGEUSDT',
        bar_interval: '1m',
        bars: [],
        indicators: [],
        venue_quality: { state: 'UNAVAILABLE', as_of: '2026-09-23T00:00:00Z' },
      },
    ],
  });
  assert.throws(() => validateSnapshot(unknownSymbol), /not supported/);

  const invalidBar = emptySnapshot({
    markets: [
      {
        symbol: 'BTCUSDT',
        bar_interval: '1m',
        bars: [
          {
            closed_at: '2026-09-23T00:00:00Z',
            open: 1,
            high: 1,
            low: 2,
            close: 1,
          },
        ],
        indicators: [],
        venue_quality: { state: 'UNAVAILABLE', as_of: '2026-09-23T00:00:00Z' },
      },
    ],
  });
  assert.throws(() => validateSnapshot(invalidBar), /invalid OHLC/);
});

test('rejects non-monotonic bars and duplicate indicator identifiers', () => {
  const market = {
    symbol: 'BTCUSDT',
    bar_interval: '1m',
    bars: [
      { closed_at: '2026-09-23T00:00:02Z', open: 2, high: 3, low: 1, close: 2 },
      { closed_at: '2026-09-23T00:00:01Z', open: 2, high: 3, low: 1, close: 2 },
    ],
    indicators: [],
    venue_quality: { state: 'UNAVAILABLE', as_of: '2026-09-23T00:00:00Z' },
  };
  assert.throws(() => validateSnapshot(emptySnapshot({ markets: [market] })), /strictly increasing/);

  const duplicates = [
    { id: 'ema:20', label: 'EMA 20', values: [] },
    { id: 'ema:20', label: 'EMA 20 duplicate', values: [] },
  ];
  assert.throws(
    () => validateSnapshot(emptySnapshot({ markets: [{ ...market, bars: [], indicators: duplicates }] })),
    /unique safe identifiers/,
  );
});

test('uses a same-origin GET only and validates the JSON response', async () => {
  let calledUrl;
  let calledOptions;
  const snapshot = emptySnapshot();
  const result = await fetchCockpitSnapshot({
    origin: 'http://127.0.0.1:5173',
    fetchImpl: async (url, options) => {
      calledUrl = url;
      calledOptions = options;
      return jsonResponse(snapshot);
    },
  });
  assert.equal(calledUrl, COCKPIT_API_PATH);
  assert.equal(calledOptions.method, 'GET');
  assert.equal(calledOptions.credentials, 'same-origin');
  assert.equal(calledOptions.cache, 'no-store');
  assert.equal(calledOptions.redirect, 'error');
  assert.deepEqual(calledOptions.headers, { Accept: 'application/json' });
  assert.deepEqual(result, snapshot);
});

test('fails closed on missing auth, absent route, and cross-origin responses', async () => {
  await assert.rejects(
    fetchCockpitSnapshot({ origin: 'http://127.0.0.1:5173', fetchImpl: async () => new Response('', { status: 401 }) }),
    (error) => error.code === 'UNAUTHORIZED',
  );
  await assert.rejects(
    fetchCockpitSnapshot({ origin: 'http://127.0.0.1:5173', fetchImpl: async () => new Response('', { status: 404 }) }),
    (error) => error.code === 'NOT_CONFIGURED',
  );
  await assert.rejects(
    fetchCockpitSnapshot({
      origin: 'http://127.0.0.1:5173',
      fetchImpl: async () => new Response('', { status: 503 }),
    }),
    (error) => error.code === 'UNAVAILABLE',
  );

  const crossOriginResponse = jsonResponse(emptySnapshot());
  Object.defineProperty(crossOriginResponse, 'url', { value: 'https://other.example/snapshot' });
  await assert.rejects(
    fetchCockpitSnapshot({
      origin: 'http://127.0.0.1:5173',
      fetchImpl: async () => crossOriginResponse,
    }),
    (error) => error.code === 'CROSS_ORIGIN',
  );
});

test('enforces the payload size limit and rejects non-JSON responses', async () => {
  const oversized = new Response('x'.repeat(MAX_SNAPSHOT_BYTES + 1), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  await assert.rejects(
    fetchCockpitSnapshot({ origin: 'http://127.0.0.1:5173', fetchImpl: async () => oversized }),
    (error) => error.code === 'RESPONSE_TOO_LARGE',
  );
  await assert.rejects(
    fetchCockpitSnapshot({
      origin: 'http://127.0.0.1:5173',
      fetchImpl: async () => new Response('<html></html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      }),
    }),
    (error) => error.code === 'NOT_CONFIGURED',
  );
});
