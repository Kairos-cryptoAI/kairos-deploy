const paths = {
  overview: <><path d="M4 19V10" /><path d="M10 19V5" /><path d="M16 19v-7" /><path d="M22 19V8" /></>,
  market: <><path d="m3 17 6-6 4 3 8-9" /><path d="M16 5h5v5" /></>,
  decisions: <><path d="M6 3.75h9l4 4V20a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4.75a1 1 0 0 1 1-1Z" /><path d="M14.5 4v4h4" /><path d="M8 12h8M8 16h8" /></>,
  journal: <><path d="M5 4.5A2.5 2.5 0 0 1 7.5 2H20v18H7.5A2.5 2.5 0 0 1 5 17.5Z" /><path d="M5 17.5A2.5 2.5 0 0 1 7.5 15H20" /><path d="M9 6h7M9 10h7" /></>,
  warning: <><path d="M12 3 2.8 19a1 1 0 0 0 .87 1.5h16.66a1 1 0 0 0 .87-1.5Z" /><path d="M12 9v4.5M12 17h.01" /></>,
  lock: <><rect x="4.5" y="10" width="15" height="11" rx="1.5" /><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" /></>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M5.5 9A7 7 0 0 1 18 6l2 2M4 16l2 2a7 7 0 0 0 12.5-3" /></>,
  menu: <><path d="M4 6h16M4 12h16M4 18h16" /></>,
  close: <><path d="m6 6 12 12M18 6 6 18" /></>,
  empty: <><path d="M7 3h7l5 5v13H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" /><path d="M14 3v5h5M8 12h7M8 16h7" /></>,
};

export function Icon({ name, size = 20, className = '' }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      focusable="false"
    >
      {paths[name]}
    </svg>
  );
}
