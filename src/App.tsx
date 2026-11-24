import { useEffect, useRef, type KeyboardEvent } from 'react';
import { useStore, TABS, canView, DEFAULT_TAB, ROLE_LABEL, type Tab } from './store/store';
import { TopBar } from './components/TopBar';
import { TerminalDrawer } from './components/TerminalDrawer';
import { SettingsModal } from './components/SettingsModal';
import { DemoGuideDrawer } from './components/DemoGuideDrawer';
import { Toasts, Button } from './components/ui';
import { Footer } from './components/Footer';
import Login from './pages/Login';
import Alerts from './pages/Alerts';
import Cases from './pages/Cases';
import Demo from './pages/Demo';
import Admin from './pages/Admin';
import Audit from './pages/Audit';
import License from './pages/License';
import Ingest from './pages/Ingest';
import type { Role } from './engine/types';

const PAGES: Record<Tab, () => JSX.Element> = { alerts: Alerts, cases: Cases, demo: Demo, admin: Admin, audit: Audit, license: License, ingest: Ingest };

function Tabs() {
  const tab = useStore((s) => s.tab);
  const role = useStore((s) => s.session!.role);
  const setTab = useStore((s) => s.setTab);
  const pending = useStore((s) => s.data.alerts.filter((a) => a.status === 'triaged' || a.status === 'new').length);
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  useEffect(() => {
    refs.current[TABS.findIndex((t) => t.id === tab)]?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }, [tab]);
  const onKey = (e: KeyboardEvent, i: number) => {
    let n = -1;
    if (e.key === 'ArrowRight') n = (i + 1) % TABS.length;
    if (e.key === 'ArrowLeft') n = (i - 1 + TABS.length) % TABS.length;
    if (e.key === 'Home') n = 0;
    if (e.key === 'End') n = TABS.length - 1;
    if (n >= 0) { e.preventDefault(); refs.current[n]?.focus(); setTab(TABS[n].id); }
  };
  return (
    <nav aria-label="Main">
      <div className="tabs-bar" role="tablist" aria-label="Riskbyte sections">
        {TABS.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => (refs.current[i] = el)}
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls="main-panel"
            tabIndex={tab === t.id ? 0 : -1}
            className="tab"
            onClick={() => setTab(t.id)}
            onKeyDown={(e) => onKey(e, i)}
          >
            {i + 1}. {t.label}
            {!canView(role, t.id) && <span className="lock" aria-label="(not available for your role)">🔒</span>}
            {t.id === 'alerts' && pending > 0 && canView(role, 'alerts') && <span className="count" aria-label={`${pending} awaiting decision`}>{pending}</span>}
          </button>
        ))}
      </div>
    </nav>
  );
}

function NoAccess({ tab }: { tab: Tab }) {
  const switchRole = useStore((s) => s.switchRole);
  const role = useStore((s) => s.session!.role);
  const target: Role = 'analyst';
  return (
    <div className="page">
      <div className="card" style={{ maxWidth: 640, margin: '40px auto', textAlign: 'center' }}>
        <div style={{ fontSize: 40 }} aria-hidden>🔒</div>
        <h2 style={{ marginTop: 12 }}>Your role cannot view this page</h2>
        <p className="muted" style={{ marginTop: 12 }}>
          You are signed in as <b>{ROLE_LABEL[role]}</b>, which can only send telemetry and view License &amp; Health. {TABS.find((t) => t.id === tab)?.label} needs an analyst or administrator.
        </p>
        <div className="row" style={{ justifyContent: 'center', marginTop: 20 }}>
          <Button onClick={() => switchRole(target)}>Switch to Security Analyst</Button>
          <Button variant="secondary" onClick={() => switchRole('admin')}>Switch to Administrator</Button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const session = useStore((s) => s.session);
  const tab = useStore((s) => s.tab);
  const setTab = useStore((s) => s.setTab);

  // Mirror tab <-> URL hash so refresh and shared links work on any static host.
  useEffect(() => {
    const fromHash = () => {
      const h = window.location.hash.replace('#', '') as Tab;
      if (TABS.some((t) => t.id === h)) setTab(h);
    };
    fromHash();
    window.addEventListener('hashchange', fromHash);
    return () => window.removeEventListener('hashchange', fromHash);
  }, [setTab]);
  useEffect(() => {
    if (session && window.location.hash !== `#${tab}`) window.history.replaceState(null, '', `#${tab}`);
  }, [tab, session]);
  useEffect(() => {
    if (session && !TABS.some((t) => `#${t.id}` === window.location.hash)) setTab(DEFAULT_TAB[session.role]);
  }, [session]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { window.scrollTo({ top: 0 }); }, [tab]);

  if (!session) return (<><Login /><Toasts /></>);

  const Page = PAGES[tab];
  return (
    <div className="shell">
      <a href="#main-panel" className="sr-only">Skip to content</a>
      <TopBar />
      <Tabs />
      <main id="main-panel" role="tabpanel" aria-labelledby={`tab-${tab}`} className="grow" tabIndex={-1}>
        {canView(session.role, tab) ? <Page key={tab} /> : <NoAccess tab={tab} />}
      </main>
      <Footer />
      <TerminalDrawer />
      <SettingsModal />
      <DemoGuideDrawer />
      <Toasts />
    </div>
  );
}
