import assert from 'node:assert/strict';
import test from 'node:test';
import { buildChartGeometry } from './chart-geometry.js';

const t1 = '2026-09-23T00:00:00Z';
const t2 = '2026-09-23T00:01:00Z';
const t3 = '2026-09-23T00:02:00Z';

function market() {
  return {
    symbol: 'BTCUSDT',
    bar_interval: '1m',
    bars: [
      { closed_at: t1, open: 10, high: 12, low: 9, close: 11 },
      { closed_at: t2, open: 11, high: 13, low: 10, close: 12 },
      { closed_at: t3, open: 12, high: 13, low: 10, close: 10.5 },
    ],
    indicators: [
      {
        id: 'ema:2',
        label: 'EMA 2',
        values: [
          { closed_at: t2, value: 11.5 },
          { closed_at: t3, value: 11.2 },
          { closed_at: '2026-09-23T00:09:00Z', value: 90 },
        ],
      },
      { id: 'rsi:14', label: 'RSI 14', values: [{ closed_at: t3, value: 55 }] },
    ],
  };
}

test('returns no geometry when there are no closed bars', () => {
  assert.equal(buildChartGeometry(null), null);
  assert.equal(buildChartGeometry({ ...market(), bars: [] }), null);
});

test('aligns selected indicator values by bar timestamp and ignores unmatched points', () => {
  const geometry = buildChartGeometry(market(), new Set(['ema:2']));
  assert.equal(geometry.bars, 3);
  assert.equal(geometry.width, 900);
  assert.equal(geometry.height, 360);
  assert.match(geometry.closePath, /^M20 /);
  assert.match(geometry.closePath, / L880 /);
  assert.equal(geometry.indicatorPaths.length, 1);
  assert.equal(geometry.indicatorPaths[0].id, 'ema:2');
  assert.match(geometry.indicatorPaths[0].path, /^M450 /);
  assert.match(geometry.indicatorPaths[0].path, / L880 /);
  assert.equal((geometry.indicatorPaths[0].path.match(/\bL/g) ?? []).length, 1);
  assert.doesNotMatch(geometry.indicatorPaths[0].path, /NaN|Infinity/);
});

test('does not include hidden indicators in the chart output', () => {
  const geometry = buildChartGeometry(market());
  assert.equal(geometry.indicatorPaths.length, 0);
});
