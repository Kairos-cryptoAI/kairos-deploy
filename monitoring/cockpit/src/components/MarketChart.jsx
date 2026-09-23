import { Icon } from './Icons.jsx';
import { buildChartGeometry } from '../chart-geometry.js';

export { buildChartGeometry } from '../chart-geometry.js';

export default function MarketChart({ market, visibleIndicatorIds, onToggleIndicator, connected }) {
  const geometry = buildChartGeometry(market, visibleIndicatorIds);
  const hasBars = market?.bars.length > 0;
  const hasEnoughBars = (market?.bars.length ?? 0) > 1;

  return (
    <section className="market-section" id="market-section" aria-labelledby="market-heading">
      <div className="section-heading">
        <div>
          <h2 id="market-heading">Рынок</h2>
          {market && <p className="section-meta">{market.symbol} · {market.bar_interval}</p>}
        </div>
        {connected && market?.indicators.length > 0 && (
          <fieldset className="indicator-controls">
            <legend>Индикаторы</legend>
            {market.indicators.map((indicator) => (
              <label key={indicator.id} className="indicator-toggle">
                <input
                  type="checkbox"
                  checked={visibleIndicatorIds.has(indicator.id)}
                  onChange={() => onToggleIndicator(indicator.id)}
                />
                <span>{indicator.label}</span>
              </label>
            ))}
          </fieldset>
        )}
      </div>
      <div className="chart-canvas" role="img" aria-label="График закрытых баров и индикаторов">
        {geometry && hasEnoughBars ? (
          <svg viewBox={'0 0 ' + geometry.width + ' ' + geometry.height} preserveAspectRatio="none">
            <path className="chart-series chart-series--close" d={geometry.closePath} />
            {geometry.indicatorPaths.map((series) => (
              <path
                key={series.id}
                className="chart-series"
                d={series.path}
                stroke={series.color}
              />
            ))}
          </svg>
        ) : (
          <div className="chart-empty">
            {!connected && <Icon className="chart-empty-icon" name="overview" size={32} />}
            <p>{connected ? (hasBars ? 'Недостаточно баров для графика' : 'Нет закрытых баров для отображения') : 'Источник данных не подключён'}</p>
            {!connected && <span>Данные появятся после подключения защищённого API</span>}
          </div>
        )}
      </div>
      {connected && market?.indicators.length > 0 && (
        <div className="indicator-legend" aria-live="polite">
          {geometry?.indicatorPaths.map((series) => (
            <span key={series.id}>
              <i style={{ backgroundColor: series.color }} />
              {series.label}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}
