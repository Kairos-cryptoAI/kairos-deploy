# Kairos Cockpit — first-slice design and data boundary

## Purpose and honest state

Private, mobile-friendly, read-only monitoring for the owner. It will show
system-observed market bars and indicators, strategy intents, LLM review,
risk decisions, venue quality, execution lifecycle and TCA. It cannot arm or
place trades.

No Cockpit API currently exists in the release. This first slice therefore
renders an explicit disconnected state and never substitutes sample prices,
candles, PnL, positions, decisions, venue health or uptime. `REJECT_ALL` is the
source-release policy, not a claim that an unavailable runtime has been read.
The page labels that value as release policy until a runtime snapshot is
available.

## Accepted visual references

- Desktop screen: `design/concept-desktop.png` (1536 × 1024 native concept).
- Mobile screen: `design/concept-mobile.png` (portrait native concept).

The mobile concept is the responsive continuation of the desktop screen; both
use the same typography, palette, row rules, open chart canvas and empty-state
language.

## Design system extracted before implementation

- **Background:** true near-black graphite, approximately `#111318`; no gradient.
- **Surfaces:** slightly lifted graphite `#171a20`; chart canvas `#13161b`.
- **Text:** warm white `#edf0f3`; secondary `#a3aab5`; dim `#727b88`.
- **Rules:** neutral graphite `#303640`; no card grid or nested panels.
- **Unavailable source:** restrained amber `#efb64b`; reserved for missing API.
- **Read-only semantic:** restrained green `#67d391`; never means trading enabled.
- **Typography:** system sans for headings/body; compact system sans for controls;
  tabular numerals for timestamp/price values. All values must come from the
  validated API, not design fixtures.
- **Desktop geometry:** 184 px navigation rail; 72 px top bar; 24 px workspace
  gutter; market canvas, five-instrument watchlist, policy rail, then a ruled
  decisions table. Main sections use open layout and thin separators.
- **Mobile geometry:** compact brand/menu row, source notice, vertically stacked
  market/list/decisions/policy sections, fixed four-item bottom navigation with
  safe-area padding.
- **Icon inventory:** simple outline icons for overview, market, decisions and
  journal; alert triangle for unavailable source; lock for read-only; refresh
  arrows for GET refresh. Inline SVG only; no decorative logo image.
- **Motion:** short state transitions only; respect reduced-motion.

## Visible-copy lock for the disconnected first screen

`Kairos`; `Обзор`; `Рынок`; `Решения`; `Журнал`; `Операционный обзор`;
`Источник данных не подключён`; `Ожидание защищённого API snapshot v1`;
`Данные появятся после подключения защищённого API`; `BTCUSDT`; `ETHUSDT`;
`SOLUSDT`; `BNBUSDT`; `XRPUSDT`; `—`; `РЕШЕНИЯ`;
`ВРЕМЯ`; `ИНСТРУМЕНТ`; `НАМЕРЕНИЕ`; `РИСК`; `ИСПОЛНЕНИЕ`; `Нет событий`;
`Политика выпуска`; `REJECT_ALL`; `Runtime API не подключён`; `Только чтение`;
`Торговые действия недоступны`;
`API v1 · ожидание snapshot`; `Обновлено —`.

The UI copy is code-native. The current disconnected state intentionally shows
only the release-policy constant and no runtime values.

## Browser verification and intentional responsive differences

- Desktop was checked at 1536 × 1024 against the desktop reference: same fixed
  left rail, top bar, warning strip, three-part market row, open chart canvas,
  decisions table and read-only policy rail.
- Mobile was checked at 390 × 844: chart, five-symbol list, empty decisions,
  policy rail and fixed four-item navigation fit in the viewport, with no
  page-level or empty-table horizontal overflow.
- The mobile footer is hidden because its trading-unavailable note is already
  repeated in the policy rail; this avoids putting secondary path text under the
  fixed bottom navigation. An empty compact decisions table hides its column
  header; populated rows keep their header and permit horizontal table scroll.
- Desktop labels remain larger than dense table/control labels. The mobile
  overview title is shortened to `Обзор`; the desktop title remains
  `Операционный обзор`.
- These are visual checks of an offline preview, not evidence that an API,
  exchange, or runtime is connected.

## API contract and security boundaries

The client contract is `kairos.cockpit.snapshot.v1`; its JSON Schema is kept at
`contracts/snapshot-v1.schema.json`. The persistence package now implements a
GET-only API producer for `/api/v1/cockpit/snapshot` behind a private
authenticated ingress. This deployment repository does not yet wire that API,
provision its dedicated read-only database role, or select/configure an SSO
proxy, so the browser fetch remains disabled until those prerequisites pass
their separate review. The only browser request is same-origin, with
`credentials: same-origin`, `cache: no-store`, redirect rejection, and a
2 MiB response limit. No token is accepted from URL/local storage, no browser
database/Redis/exchange access exists, and there are no mutation methods.

Local UI preview keeps the API disabled by default. Enable the fetch only with
`VITE_COCKPIT_API_ENABLED=true` after an authenticated same-origin producer and
proxy are implemented and reviewed.

Deploy only behind a separately reviewed authenticated private-network proxy.
Do not add a public Docker port or serve this UI as an unauthenticated service.
The initial local Vite server binds to `127.0.0.1` only.

Snapshot rows are bounded, enums are allow-listed, and unrecognized schema
versions fail closed. The v1 schema intentionally excludes private keys,
account balances and blind-campaign PnL.
