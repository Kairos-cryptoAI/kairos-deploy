const symbols = ['BTCUSDT', 'ETHUSDT', 'SOLUSDT', 'BNBUSDT', 'XRPUSDT'];

export default function Watchlist({ markets, selectedSymbol, onSelect }) {
  const bySymbol = new Map((markets ?? []).map((market) => [market.symbol, market]));

  return (
    <section className="watchlist" aria-labelledby="watchlist-heading">
      <h2 id="watchlist-heading">Инструменты</h2>
      <div className="watchlist-rows">
        {symbols.map((symbol) => {
          const market = bySymbol.get(symbol);
          const latest = market?.bars.at(-1);
          return (
            <button
              aria-current={selectedSymbol === symbol ? 'true' : undefined}
              className="watchlist-row"
              key={symbol}
              onClick={() => onSelect(symbol)}
              type="button"
            >
              <span>{symbol}</span>
              <span className="watchlist-value">
                {latest ? latest.close.toLocaleString('ru-RU', { maximumSignificantDigits: 8 }) : '—'}
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}
