import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CockpitApiError, fetchCockpitSnapshot } from './api.js';
import DecisionTable from './components/DecisionTable.jsx';
import EmptyState from './components/EmptyState.jsx';
import { Icon } from './components/Icons.jsx';
import JournalTables from './components/JournalTables.jsx';
import MarketChart from './components/MarketChart.jsx';
import PolicyRail from './components/PolicyRail.jsx';
import Watchlist from './components/Watchlist.jsx';

const navigation = [
  { id: 'overview', label: 'Обзор', icon: 'overview' },
  { id: 'market', label: 'Рынок', icon: 'market' },
  { id: 'decisions', label: 'Решения', icon: 'decisions' },
  { id: 'journal', label: 'Журнал', icon: 'journal' },
];

const pageTitles = {
  overview: 'Операционный обзор',
  market: 'Рынок',
  decisions: 'Решения',
  journal: 'Журнал',
};

function errorCopy(error) {
  if (!(error instanceof CockpitApiError)) {
    return { title: 'Источник данных не подключён', detail: 'Ожидание защищённого API snapshot v1' };
  }
  if (error.code === 'UNAUTHORIZED') {
    return { title: 'Доступ к данным не подтверждён', detail: 'Войдите через защищённый шлюз и обновите snapshot' };
  }
  if (error.code === 'INVALID_SNAPSHOT' || error.code === 'UNSUPPORTED_VERSION' || error.code === 'INVALID_RESPONSE') {
    return { title: 'Ответ API не прошёл проверку', detail: 'Данные скрыты до получения корректного snapshot v1' };
  }
  if (error.code === 'RESPONSE_TOO_LARGE') {
    return { title: 'Ответ API превышает лимит', detail: 'Данные скрыты; размер snapshot ограничен 2 MiB' };
  }
  return { title: 'Источник данных не подключён', detail: 'Ожидание защищённого API snapshot v1' };
}

function useCockpitSnapshot() {
  const apiEnabled = import.meta.env.VITE_COCKPIT_API_ENABLED === 'true';
  const [snapshot, setSnapshot] = useState(null);
  const [request, setRequest] = useState({ state: 'loading', error: null });
  const busy = useRef(false);

  const refresh = useCallback(async () => {
    if (!apiEnabled) {
      setSnapshot(null);
      setRequest({ state: 'error', error: new CockpitApiError('NOT_CONFIGURED', 'API producer is not enabled') });
      return;
    }
    if (busy.current) return;
    busy.current = true;
    setRequest({ state: 'loading', error: null });
    try {
      const next = await fetchCockpitSnapshot();
      setSnapshot(next);
      setRequest({ state: 'ready', error: null });
    } catch (error) {
      setSnapshot(null);
      setRequest({ state: 'error', error });
    } finally {
      busy.current = false;
    }
  }, [apiEnabled]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!apiEnabled) return undefined;
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(timer);
  }, [apiEnabled, refresh]);

  return { snapshot, request, refresh, apiEnabled };
}

function Navigation({ active, onSelect, mobile = false }) {
  return (
    <nav aria-label="Разделы Cockpit" className={mobile ? 'mobile-nav' : 'desktop-nav'}>
      {navigation.map((item) => (
        <button
          aria-current={active === item.id ? 'page' : undefined}
          className={active === item.id ? 'nav-item nav-item--active' : 'nav-item'}
          key={item.id}
          onClick={() => onSelect(item.id)}
          type="button"
        >
          <Icon name={item.icon} size={20} />
          <span>{item.label}</span>
        </button>
      ))}
    </nav>
  );
}

function SourceNotice({ request }) {
  if (request.state === 'ready') return null;
  const copy = request.state === 'loading'
    ? { title: 'Проверяем защищённый API', detail: 'Ожидание snapshot v1' }
    : errorCopy(request.error);

  return (
    <div className="source-notice" role="status" aria-live="polite">
      <Icon name="warning" size={21} />
      <strong>{copy.title}</strong>
      <span>{copy.detail}</span>
    </div>
  );
}

function OverviewView({ snapshot, selectedSymbol, onSelectSymbol }) {
  const selectedMarket = snapshot?.markets.find((market) => market.symbol === selectedSymbol) ?? null;
  return (
    <div className="main-grid main-grid--overview">
      <MarketChart
        connected={Boolean(snapshot)}
        market={selectedMarket}
        visibleIndicatorIds={new Set()}
        onToggleIndicator={() => {}}
      />
      <Watchlist
        markets={snapshot?.markets ?? []}
        selectedSymbol={selectedSymbol}
        onSelect={onSelectSymbol}
      />
      <PolicyRail
        policy={snapshot?.system.strategy_policy ?? 'REJECT_ALL'}
        runtimeState={snapshot?.system.runtime_state}
      />
      <DecisionTable decisions={snapshot?.decisions ?? []} compact />
    </div>
  );
}

function MarketView({ snapshot, selectedSymbol, onSelectSymbol }) {
  const selectedMarket = snapshot?.markets.find((market) => market.symbol === selectedSymbol) ?? null;
  const [visibleIndicatorIds, setVisibleIndicatorIds] = useState(new Set());
  const toggleIndicator = (id) => {
    setVisibleIndicatorIds((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  useEffect(() => {
    const available = new Set(selectedMarket?.indicators.map((indicator) => indicator.id) ?? []);
    setVisibleIndicatorIds((previous) => new Set([...previous].filter((id) => available.has(id))));
  }, [selectedMarket]);

  return (
    <div className="main-grid main-grid--market">
      <MarketChart
        connected={Boolean(snapshot)}
        market={selectedMarket}
        visibleIndicatorIds={visibleIndicatorIds}
        onToggleIndicator={toggleIndicator}
      />
      <Watchlist
        markets={snapshot?.markets ?? []}
        selectedSymbol={selectedSymbol}
        onSelect={onSelectSymbol}
      />
      <PolicyRail
        policy={snapshot?.system.strategy_policy ?? 'REJECT_ALL'}
        runtimeState={snapshot?.system.runtime_state}
      />
      {snapshot && selectedMarket?.indicators.length === 0 && (
        <p className="indicator-empty">Для выбранного инструмента в snapshot нет индикаторов.</p>
      )}
    </div>
  );
}

function DecisionsView({ snapshot }) {
  return (
    <div className="main-grid main-grid--content">
      <DecisionTable decisions={snapshot?.decisions ?? []} />
      <PolicyRail
        policy={snapshot?.system.strategy_policy ?? 'REJECT_ALL'}
        runtimeState={snapshot?.system.runtime_state}
      />
    </div>
  );
}

function JournalView({ snapshot }) {
  return (
    <div className="main-grid main-grid--content">
      <div className="journal-column">
        <JournalTables lifecycle={snapshot?.lifecycle ?? []} tca={snapshot?.tca ?? []} />
      </div>
      <PolicyRail
        policy={snapshot?.system.strategy_policy ?? 'REJECT_ALL'}
        runtimeState={snapshot?.system.runtime_state}
      />
    </div>
  );
}

export default function App() {
  const { snapshot, request, refresh, apiEnabled } = useCockpitSnapshot();
  const [active, setActive] = useState('overview');
  const [selectedSymbol, setSelectedSymbol] = useState('BTCUSDT');
  const [menuOpen, setMenuOpen] = useState(false);

  const lastUpdated = useMemo(() => {
    if (!snapshot) return 'Обновлено —';
    const rendered = new Intl.DateTimeFormat('ru-RU', {
      timeZone: 'Europe/Moscow',
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(snapshot.generated_at));
    return 'Обновлено ' + rendered;
  }, [snapshot]);

  useEffect(() => {
    function closeOnEscape(event) {
      if (event.key === 'Escape') setMenuOpen(false);
    }
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, []);

  const selectNavigation = (id) => {
    setActive(id);
    setMenuOpen(false);
  window.scrollTo({ top: 0, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  };

  let content;
  if (active === 'market') {
    content = <MarketView snapshot={snapshot} selectedSymbol={selectedSymbol} onSelectSymbol={setSelectedSymbol} />;
  } else if (active === 'decisions') {
    content = <DecisionsView snapshot={snapshot} />;
  } else if (active === 'journal') {
    content = <JournalView snapshot={snapshot} />;
  } else {
    content = <OverviewView snapshot={snapshot} selectedSymbol={selectedSymbol} onSelectSymbol={setSelectedSymbol} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a aria-label="Kairos — Обзор" className="wordmark" href="#top" onClick={() => selectNavigation('overview')}>
          Kairos
        </a>
        <Navigation active={active} onSelect={selectNavigation} />
        <div className="sidebar-foot">
          <span>Только чтение</span>
          <span>API v1</span>
        </div>
      </aside>

      <div className="page-frame" id="top">
        <header className="topbar">
          <div className="brand-mobile">
            <button
              aria-expanded={menuOpen}
              aria-label={menuOpen ? 'Закрыть меню' : 'Открыть меню'}
              className="icon-button mobile-menu-button"
              onClick={() => setMenuOpen((open) => !open)}
              type="button"
            >
              <Icon name={menuOpen ? 'close' : 'menu'} size={23} />
            </button>
            <a aria-label="Kairos — Обзор" className="wordmark wordmark--mobile" href="#top" onClick={() => selectNavigation('overview')}>
              Kairos
            </a>
          </div>
          <h1>
            {active === 'overview' ? (
              <>
                <span className="desktop-title">Операционный обзор</span>
                <span className="mobile-title">Обзор</span>
              </>
            ) : pageTitles[active]}
          </h1>
          <div className="topbar-tools">
            <span className="api-status">API v1 · {snapshot ? 'snapshot принят' : 'ожидание snapshot'}</span>
            <span aria-label={lastUpdated} className="updated-at">{lastUpdated}</span>
            <button
              className="refresh-button"
              aria-label="Обновить данные"
              disabled={!apiEnabled || request.state === 'loading'}
              title={!apiEnabled ? 'Read-only API producer не настроен' : undefined}
              onClick={() => void refresh()}
              type="button"
            >
              <Icon className={request.state === 'loading' ? 'refresh-icon refresh-icon--busy' : 'refresh-icon'} name="refresh" size={18} />
              <span>Обновить</span>
            </button>
          </div>
        </header>

        {menuOpen && (
          <div className="mobile-menu-panel">
            <Navigation active={active} onSelect={selectNavigation} />
          </div>
        )}

        <main className="main-content">
          <SourceNotice request={request} />
          {content}
          <footer className="page-footer">
            <span>GET {"/api/v1/cockpit/snapshot"}</span>
            <span>Торговые действия недоступны</span>
          </footer>
        </main>
      </div>

      <Navigation active={active} onSelect={selectNavigation} mobile />
    </div>
  );
}
