import EmptyState from './EmptyState.jsx';
import { formatTime } from './DecisionTable.jsx';

const eventLabels = {
  INTENT: 'Намерение',
  REVIEW: 'LLM review',
  RISK: 'Риск',
  ORDER: 'Ордер',
  FILL: 'Исполнение',
  PROTECTION: 'Защита',
  TIMEOUT: 'Тайм-аут',
  RECOVERY: 'Восстановление',
};

export default function JournalTables({ lifecycle, tca }) {
  return (
    <>
      <section className="table-section" id="journal-section" aria-labelledby="journal-heading">
        <div className="section-heading section-heading--row">
          <h2 id="journal-heading">Журнал событий</h2>
          <span className="section-meta">Неизменённая последовательность жизненного цикла</span>
        </div>
        {lifecycle.length === 0 ? (
          <EmptyState compact>Нет событий</EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr><th scope="col">Время</th><th scope="col">Инструмент</th><th scope="col">Событие</th><th scope="col">Состояние</th></tr>
              </thead>
              <tbody>
                {lifecycle.map((event) => (
                  <tr key={event.id}>
                    <td className="tabular">{formatTime(event.occurred_at)}</td>
                    <td>{event.symbol}</td>
                    <td>{eventLabels[event.event_type]}</td>
                    <td>{event.state}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="table-section" aria-labelledby="tca-heading">
        <div className="section-heading section-heading--row">
          <h2 id="tca-heading">TCA</h2>
          <span className="section-meta">Комиссии, проскальзывание и funding</span>
        </div>
        {tca.length === 0 ? (
          <EmptyState compact>Нет событий</EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr><th scope="col">Время</th><th scope="col">Ссылка</th><th scope="col">Комиссия, bps</th><th scope="col">Проскальзывание, bps</th><th scope="col">Funding, bps</th></tr>
              </thead>
              <tbody>
                {tca.map((row) => (
                  <tr key={row.reference_id}>
                    <td className="tabular">{formatTime(row.measured_at)}</td>
                    <td>{row.reference_id}</td>
                    <td className="tabular">{row.fee_bps.toFixed(2)}</td>
                    <td className="tabular">{row.slippage_bps.toFixed(2)}</td>
                    <td className="tabular">{row.funding_bps == null ? '—' : row.funding_bps.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
