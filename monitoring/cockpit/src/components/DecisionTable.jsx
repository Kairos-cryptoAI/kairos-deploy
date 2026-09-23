import EmptyState from './EmptyState.jsx';

const labels = {
  ALLOW: 'Разрешено',
  VETO: 'Отклонено',
  DEFER: 'Отложено',
  NOT_REQUESTED: 'Не запрошен',
  APPROVED: 'Допущено',
  CREATED: 'Создано',
  REJECTED: 'Отклонено',
  EXPIRED: 'Истекло',
  NOT_REQUESTED_EXECUTION: 'Не запрошено',
  PENDING: 'Ожидает',
  PARTIAL: 'Частично',
  FILLED: 'Исполнено',
  CANCELLED: 'Отменено',
  UNKNOWN: 'Неизвестно',
};

function localized(value) {
  if (value === 'NOT_REQUESTED' && Object.hasOwn(labels, 'NOT_REQUESTED')) return labels.NOT_REQUESTED;
  return labels[value] ?? value;
}

export function formatTime(value) {
  return new Intl.DateTimeFormat('ru-RU', {
    timeZone: 'Europe/Moscow',
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(new Date(value));
}

export default function DecisionTable({ decisions, compact = false }) {
  const rows = compact ? decisions.slice(0, 8) : decisions;
  return (
    <section className="table-section" id="decisions-section" aria-labelledby="decisions-heading">
      <div className="section-heading section-heading--row">
        <h2 id="decisions-heading">Решения</h2>
        {!compact && <span className="section-meta">Последние решения стратегии и контролей</span>}
      </div>
      <div className="table-scroll">
        <table
          className={compact
            ? rows.length === 0
              ? 'decision-table decision-table--compact decision-table--compact-empty'
              : 'decision-table decision-table--compact'
            : 'decision-table'}
        >
          <thead>
            <tr>
              <th scope="col">Время</th>
              <th scope="col">Инструмент</th>
              <th scope="col">Намерение</th>
              {!compact && <th scope="col">LLM review</th>}
              <th scope="col">Риск</th>
              <th scope="col">Исполнение</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td className="empty-cell" colSpan={compact ? 5 : 6}>
                  <EmptyState compact>Нет событий</EmptyState>
                </td>
              </tr>
            ) : rows.map((decision) => (
              <tr key={decision.id}>
                <td className="tabular">{formatTime(decision.created_at)}</td>
                <td>{decision.symbol}</td>
                <td>
                  <span className="intent-label">{decision.intent_side}</span>
                  <small>{localized(decision.candidate_state)}</small>
                </td>
                {!compact && <td>{localized(decision.llm_review)}</td>}
                <td>{localized(decision.risk_decision)}</td>
                <td>{localized(decision.execution_state)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
