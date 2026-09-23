function linePath(points, scaleX, scaleY) {
  const visible = points.filter((point) => Number.isFinite(point.index) && Number.isFinite(point.value));
  return visible
    .map((point, index) => (index === 0 ? 'M' : 'L') + scaleX(point.index) + ' ' + scaleY(point.value))
    .join(' ');
}

export function buildChartGeometry(market, visibleIndicatorIds = new Set()) {
  if (!market || market.bars.length === 0) return null;

  const width = 900;
  const height = 360;
  const padding = { top: 18, right: 20, bottom: 24, left: 20 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const rangeValues = market.bars.flatMap((bar) => [bar.low, bar.high]);
  const selectedIndicators = market.indicators.filter((indicator) =>
    visibleIndicatorIds.has(indicator.id),
  );
  for (const indicator of selectedIndicators) {
    for (const point of indicator.values) {
      if (Number.isFinite(point.value)) rangeValues.push(point.value);
    }
  }

  const minimum = Math.min(...rangeValues);
  const maximum = Math.max(...rangeValues);
  const spread = maximum - minimum;
  const paddingValue = spread === 0 ? Math.abs(maximum) * 0.04 || 1 : spread * 0.08;
  const floor = minimum - paddingValue;
  const ceiling = maximum + paddingValue;
  const denominator = Math.max(1, market.bars.length - 1);
  const scaleX = (index) => padding.left + (index / denominator) * plotWidth;
  const scaleY = (value) => padding.top + ((ceiling - value) / (ceiling - floor)) * plotHeight;
  const barIndexes = new Map(market.bars.map((bar, index) => [bar.closed_at, index]));
  const closePath = linePath(
    market.bars.map((bar, index) => ({ index, value: bar.close })),
    scaleX,
    scaleY,
  );
  const indicatorPaths = selectedIndicators.map((indicator, index) => ({
    id: indicator.id,
    label: indicator.label,
    color: ['#eab54f', '#8ca8d6', '#72c49c', '#c99acc'][index % 4],
    path: linePath(
      indicator.values.map((point) => ({
        index: barIndexes.get(point.closed_at),
        value: point.value,
      })),
      scaleX,
      scaleY,
    ),
  }));

  return { width, height, closePath, indicatorPaths, bars: market.bars.length };
}
