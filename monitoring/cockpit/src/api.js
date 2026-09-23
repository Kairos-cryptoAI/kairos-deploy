export const COCKPIT_API_PATH = '/api/v1/cockpit/snapshot';
export const SNAPSHOT_SCHEMA_VERSION = 'kairos.cockpit.snapshot.v1';
export const MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024;

const SYMBOLS = new Set(['BTCUSDT', 'ETHUSDT', 'SOLUSDT', 'BNBUSDT', 'XRPUSDT']);
const RUNTIME_STATES = new Set(['RUNNING', 'DEGRADED', 'STOPPED']);
const TRADING_MODES = new Set(['DRY_RUN', 'PAPER', 'LIVE']);
const POLICIES = new Set(['REJECT_ALL', 'ALLOWLIST']);
const INTERVALS = new Set(['1m', '5m', '15m', '1h', '4h', '1d']);
const VENUE_STATES = new Set(['HEALTHY', 'DEGRADED', 'STALE', 'UNAVAILABLE']);
const CANDIDATE_STATES = new Set(['CREATED', 'REJECTED', 'EXPIRED']);
const INTENT_SIDES = new Set(['LONG', 'SHORT', 'FLAT']);
const REVIEW_STATES = new Set(['ALLOW', 'VETO', 'DEFER', 'NOT_REQUESTED']);
const RISK_STATES = new Set(['APPROVED', 'VETO', 'DEFER']);
const EXECUTION_STATES = new Set([
  'NOT_REQUESTED',
  'PENDING',
  'PARTIAL',
  'FILLED',
  'CANCELLED',
  'REJECTED',
  'UNKNOWN',
]);
const LIFECYCLE_TYPES = new Set([
  'INTENT',
  'REVIEW',
  'RISK',
  'ORDER',
  'FILL',
  'PROTECTION',
  'TIMEOUT',
  'RECOVERY',
]);

export class CockpitApiError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CockpitApiError';
    this.code = code;
  }
}

function fail(message) {
  throw new CockpitApiError('INVALID_SNAPSHOT', message);
}

function record(value, label, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(label + ' must be an object');
  }
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    fail(label + ' contains an unsupported field');
  }
  if (required.some((key) => !Object.hasOwn(value, key))) {
    fail(label + ' is missing a required field');
  }
  return value;
}

function array(value, label, maximum) {
  if (!Array.isArray(value) || value.length > maximum) {
    fail(label + ' must be an array of at most ' + maximum + ' items');
  }
  return value;
}

function boundedString(value, label, maximum, allowEmpty = false) {
  if (
    typeof value !== 'string' ||
    value.length > maximum ||
    (!allowEmpty && value.trim().length === 0)
  ) {
    fail(label + ' must be a bounded string');
  }
  return value;
}

function enumValue(value, label, allowed) {
  if (!allowed.has(value)) fail(label + ' is not supported');
  return value;
}

function isoDateTime(value, label) {
  boundedString(value, label, 40);
  if (!/(?:[zZ]|[+-]\d{2}:\d{2})$/.test(value) || !Number.isFinite(Date.parse(value))) {
    fail(label + ' must be an ISO-8601 timestamp with timezone');
  }
  return value;
}

function finiteNumber(value, label, minimum = -Infinity) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum) {
    fail(label + ' must be a finite number');
  }
  return value;
}

function validateSystem(value) {
  const system = record(
    value,
    'system',
    ['runtime_state', 'trading_mode', 'strategy_policy', 'readiness'],
  );
  enumValue(system.runtime_state, 'system.runtime_state', RUNTIME_STATES);
  enumValue(system.trading_mode, 'system.trading_mode', TRADING_MODES);
  enumValue(system.strategy_policy, 'system.strategy_policy', POLICIES);
  const readiness = record(
    system.readiness,
    'system.readiness',
    ['technical_paper_ready', 'paper_qualified', 'alpha_ready', 'live_ready'],
  );
  for (const key of Object.keys(readiness)) {
    if (typeof readiness[key] !== 'boolean') fail('system.readiness values must be boolean');
  }
}

function validateBars(value, label) {
  const bars = array(value, label, 500);
  let previousTime = -Infinity;
  for (const [index, value] of bars.entries()) {
    const bar = record(value, label + '[' + index + ']', [
      'closed_at',
      'open',
      'high',
      'low',
      'close',
    ]);
    const time = Date.parse(isoDateTime(bar.closed_at, label + '.closed_at'));
    const open = finiteNumber(bar.open, label + '.open', Number.MIN_VALUE);
    const high = finiteNumber(bar.high, label + '.high', Number.MIN_VALUE);
    const low = finiteNumber(bar.low, label + '.low', Number.MIN_VALUE);
    const close = finiteNumber(bar.close, label + '.close', Number.MIN_VALUE);
    if (time <= previousTime) fail(label + ' timestamps must be strictly increasing');
    if (low > Math.min(open, close) || high < Math.max(open, close) || low > high) {
      fail(label + ' contains invalid OHLC ordering');
    }
    previousTime = time;
  }
}

function validateIndicators(value, label) {
  const indicators = array(value, label, 16);
  const ids = new Set();
  for (const [index, value] of indicators.entries()) {
    const indicator = record(value, label + '[' + index + ']', ['id', 'label', 'values']);
    boundedString(indicator.id, label + '.id', 64);
    if (!/^[a-z0-9:_-]+$/.test(indicator.id) || ids.has(indicator.id)) {
      fail(label + ' ids must be unique safe identifiers');
    }
    ids.add(indicator.id);
    boundedString(indicator.label, label + '.label', 64);
    const values = array(indicator.values, label + '.values', 500);
    let previousTime = -Infinity;
    for (const [valueIndex, point] of values.entries()) {
      const item = record(point, label + '.values[' + valueIndex + ']', ['closed_at', 'value']);
      const time = Date.parse(isoDateTime(item.closed_at, label + '.closed_at'));
      finiteNumber(item.value, label + '.value');
      if (time <= previousTime) fail(label + ' timestamps must be strictly increasing');
      previousTime = time;
    }
  }
}

function validateMarkets(value) {
  const markets = array(value, 'markets', 5);
  const seenSymbols = new Set();
  for (const [index, value] of markets.entries()) {
    const market = record(
      value,
      'markets[' + index + ']',
      ['symbol', 'bar_interval', 'bars', 'indicators', 'venue_quality'],
    );
    enumValue(market.symbol, 'market.symbol', SYMBOLS);
    if (seenSymbols.has(market.symbol)) fail('markets must not contain duplicate symbols');
    seenSymbols.add(market.symbol);
    enumValue(market.bar_interval, 'market.bar_interval', INTERVALS);
    validateBars(market.bars, 'market.bars');
    validateIndicators(market.indicators, 'market.indicators');

    const venue = record(
      market.venue_quality,
      'market.venue_quality',
      ['state', 'as_of', 'spread_bps', 'book_age_ms', 'slippage_bps'],
      ['state', 'as_of'],
    );
    enumValue(venue.state, 'venue_quality.state', VENUE_STATES);
    isoDateTime(venue.as_of, 'venue_quality.as_of');
    for (const key of ['spread_bps', 'slippage_bps']) {
      if (Object.hasOwn(venue, key) && venue[key] !== null) {
        finiteNumber(venue[key], 'venue_quality.' + key, key === 'spread_bps' ? 0 : -Infinity);
      }
    }
    if (Object.hasOwn(venue, 'book_age_ms') && venue.book_age_ms !== null) {
      finiteNumber(venue.book_age_ms, 'venue_quality.book_age_ms', 0);
      if (!Number.isInteger(venue.book_age_ms)) fail('venue_quality.book_age_ms must be an integer');
    }
  }
}

function validateDecisions(items) {
  for (const [index, item] of array(items, 'decisions', 200).entries()) {
    const decision = record(item, 'decisions[' + index + ']', [
      'id',
      'created_at',
      'symbol',
      'strategy_id',
      'intent_side',
      'candidate_state',
      'llm_review',
      'risk_decision',
      'execution_state',
      'reason_code',
    ]);
    boundedString(decision.id, 'decision.id', 96);
    isoDateTime(decision.created_at, 'decision.created_at');
    enumValue(decision.symbol, 'decision.symbol', SYMBOLS);
    boundedString(decision.strategy_id, 'decision.strategy_id', 96);
    enumValue(decision.intent_side, 'decision.intent_side', INTENT_SIDES);
    enumValue(decision.candidate_state, 'decision.candidate_state', CANDIDATE_STATES);
    enumValue(decision.llm_review, 'decision.llm_review', REVIEW_STATES);
    enumValue(decision.risk_decision, 'decision.risk_decision', RISK_STATES);
    enumValue(decision.execution_state, 'decision.execution_state', EXECUTION_STATES);
    if (decision.reason_code !== null) boundedString(decision.reason_code, 'decision.reason_code', 96);
  }
}

function validateLifecycle(items) {
  for (const [index, item] of array(items, 'lifecycle', 200).entries()) {
    const event = record(item, 'lifecycle[' + index + ']', [
      'id',
      'occurred_at',
      'symbol',
      'event_type',
      'state',
    ]);
    boundedString(event.id, 'lifecycle.id', 96);
    isoDateTime(event.occurred_at, 'lifecycle.occurred_at');
    enumValue(event.symbol, 'lifecycle.symbol', SYMBOLS);
    enumValue(event.event_type, 'lifecycle.event_type', LIFECYCLE_TYPES);
    boundedString(event.state, 'lifecycle.state', 64);
  }
}

function validateTca(items) {
  for (const [index, item] of array(items, 'tca', 200).entries()) {
    const row = record(
      item,
      'tca[' + index + ']',
      ['reference_id', 'measured_at', 'fee_bps', 'slippage_bps', 'funding_bps'],
      ['reference_id', 'measured_at', 'fee_bps', 'slippage_bps'],
    );
    boundedString(row.reference_id, 'tca.reference_id', 96);
    isoDateTime(row.measured_at, 'tca.measured_at');
    finiteNumber(row.fee_bps, 'tca.fee_bps', 0);
    finiteNumber(row.slippage_bps, 'tca.slippage_bps');
    if (Object.hasOwn(row, 'funding_bps') && row.funding_bps !== null) {
      finiteNumber(row.funding_bps, 'tca.funding_bps');
    }
  }
}

export function validateSnapshot(value) {
  const snapshot = record(
    value,
    'snapshot',
    ['schema_version', 'generated_at', 'system', 'markets', 'decisions', 'lifecycle', 'tca'],
  );
  if (snapshot.schema_version !== SNAPSHOT_SCHEMA_VERSION) {
    throw new CockpitApiError('UNSUPPORTED_VERSION', 'Snapshot schema version is unsupported');
  }
  isoDateTime(snapshot.generated_at, 'generated_at');
  validateSystem(snapshot.system);
  validateMarkets(snapshot.markets);
  validateDecisions(snapshot.decisions);
  validateLifecycle(snapshot.lifecycle);
  validateTca(snapshot.tca);
  return snapshot;
}

async function readLimitedBody(response) {
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > MAX_SNAPSHOT_BYTES) {
    throw new CockpitApiError('RESPONSE_TOO_LARGE', 'Snapshot exceeds the response size limit');
  }
  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_SNAPSHOT_BYTES) {
      throw new CockpitApiError('RESPONSE_TOO_LARGE', 'Snapshot exceeds the response size limit');
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_SNAPSHOT_BYTES) {
        await reader.cancel();
        throw new CockpitApiError('RESPONSE_TOO_LARGE', 'Snapshot exceeds the response size limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export async function fetchCockpitSnapshot({ fetchImpl = globalThis.fetch, origin } = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new CockpitApiError('UNAVAILABLE', 'Fetch is unavailable');
  }
  const requestOrigin = origin || globalThis.location?.origin;
  if (!requestOrigin) throw new CockpitApiError('UNAVAILABLE', 'Browser origin is unavailable');

  let response;
  try {
    response = await fetchImpl(COCKPIT_API_PATH, {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
  } catch (error) {
    if (error instanceof CockpitApiError) throw error;
    throw new CockpitApiError('UNAVAILABLE', 'Cockpit API is unreachable');
  }

  if (response.url) {
    try {
      if (new URL(response.url, requestOrigin).origin !== new URL(requestOrigin).origin) {
        throw new CockpitApiError('CROSS_ORIGIN', 'Cross-origin API responses are not accepted');
      }
    } catch (error) {
      if (error instanceof CockpitApiError) throw error;
      throw new CockpitApiError('INVALID_RESPONSE', 'API response URL is invalid');
    }
  }
  if (response.status === 401 || response.status === 403) {
    throw new CockpitApiError('UNAUTHORIZED', 'Cockpit API did not authorize this request');
  }
  if (response.status === 404) {
    throw new CockpitApiError('NOT_CONFIGURED', 'Cockpit snapshot endpoint is not configured');
  }
  if (!response.ok) throw new CockpitApiError('UNAVAILABLE', 'Cockpit API returned an unavailable response');
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.includes('application/json')) {
    if (contentType.includes('text/html')) {
      throw new CockpitApiError('NOT_CONFIGURED', 'Cockpit snapshot endpoint is not configured');
    }
    throw new CockpitApiError('INVALID_RESPONSE', 'Cockpit API did not return JSON');
  }

  let payload;
  try {
    payload = JSON.parse(await readLimitedBody(response));
  } catch (error) {
    if (error instanceof CockpitApiError) throw error;
    throw new CockpitApiError('INVALID_RESPONSE', 'Cockpit API returned invalid JSON');
  }
  return validateSnapshot(payload);
}
