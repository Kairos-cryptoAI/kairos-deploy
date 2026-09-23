import { Icon } from './Icons.jsx';

export default function PolicyRail({ policy = 'REJECT_ALL', runtimeState }) {
  return (
    <aside className="policy-rail" aria-label="Политика и режим Cockpit">
      <div className="policy-block">
        <p className="eyebrow">{runtimeState ? 'Политика системы' : 'Политика выпуска'}</p>
        <strong className="policy-value">{policy}</strong>
        {!runtimeState && <span className="policy-note">Runtime API не подключён</span>}
        {runtimeState && <span className="runtime-value">Сервис: {runtimeState}</span>}
      </div>
      <div className="readonly-block">
        <Icon name="lock" size={21} />
        <div>
          <strong>Только чтение</strong>
          <p>Торговые действия недоступны</p>
        </div>
      </div>
    </aside>
  );
}
