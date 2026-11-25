import { useEffect } from 'react';
import { useStore, VIEWS, WORKSPACE_LABEL, WORKSPACE_ROLE, syncFromHash, tierStatus, type Workspace } from './store/store';
import { MonitorPill, AiPill } from './components/Live';
import { TOKENS } from './engine/auth';
import { Toasts } from './components/ui';
import Landing from './pages/Landing';
import AnalystWorkspace from './pages/Analyst';
import AdminWorkspace from './pages/Admin';
import IngestWorkspace from './pages/Ingest';
import DemoWorkspace from './pages/Demo';
import { CREDIT } from './data/copy';

const PAGES: Record<Workspace, () => JSX.Element> = { analyst: AnalystWorkspace, admin: AdminWorkspace, ingest: IngestWorkspace, demo: DemoWorkspace };

const SUBTITLE: Record<string, string> = {
  'analyst/overview': 'What needs your attention right now',
  'analyst/alerts': 'Every detection, the agent’s assessment, and the action waiting for you',
  'analyst/incidents': 'Alerts on the same host or user, grouped into one incident',
  'analyst/activity': 'Everything the AI agent has done, newest first',
  'admin/overview': 'Platform health across every organization',
  'admin/orgs': 'Organizations whose telemetry Riskbyte monitors',
  'admin/agent': 'AI provider and how much autonomy the agent has',
  'admin/rules': 'Sigma-style detection content',
  'admin/intel': 'Known-bad indicators used for enrichment',
  'admin/ledger': 'SHA-256 hash-chained record of every action',
  'admin/system': 'License, storage, API and data management',
  'ingest/overview': 'Collectors, endpoints and throughput per organization',
  'ingest/logs': 'Every user action, API call, scan, agent step and ledger write, in real time',
  'ingest/stream': 'Raw normalized events as they arrive',
  'ingest/send': 'Post a batch to the ingest API',
  'ingest/console': 'Live pipeline log',
  'demo/attacks': 'Launch simulated attacks against a monitored organization',
};

function Sidebar({ ws }: { ws: Workspace }) {
  const view = useStore((s) => s.view);
  const go = useStore((s) => s.go);
  const leave = useStore((s) => s.leave);
  const pending = useStore((s) => s.data.alerts.filter((a) => a.status === 'triaged' || a.status === 'new').length);
  const openInc = useStore((s) => s.data.cases.filter((c) => c.status === 'open').length);
  const counts: Record<string, number> = ws === 'analyst' ? { alerts: pending, incidents: openInc } : {};
  return (
    <aside className="sidebar" aria-label="Workspace navigation">
      <button type="button" className="side-brand" onClick={leave} aria-label="Riskbyte home"><span className="dot" aria-hidden />Riskbyte</button>
      <div className="side-ws">
        <div className="label">Workspace</div>
        <b>{WORKSPACE_LABEL[ws]}</b>
        <span className="small">{ws === 'demo' ? 'Simulation only' : `Signed in · ${WORKSPACE_ROLE[ws]}`}</span>
      </div>
      <nav className="side-nav">
        {VIEWS[ws].map((v) => (
          <button key={v.id} type="button" aria-current={view === v.id ? 'page' : undefined} onClick={() => go(v.id)}>
            <span className="ic" aria-hidden>{v.icon}</span>{v.label}
            {counts[v.id] ? <span className="count">{counts[v.id]}</span> : null}
          </button>
        ))}
      </nav>
      <div className="side-foot">
        <span className="tok">token: {TOKENS[WORKSPACE_ROLE[ws]]}</span>
        <button type="button" className="switch-btn" onClick={leave}>⇄ Switch workspace</button>
        <span className="credit">{CREDIT}</span>
      </div>
    </aside>
  );
}

function StatusRow({ ws }: { ws: Workspace }) {
  const audit = useStore((s) => s.audit);
  const tier = useStore((s) => (ws === 'demo' ? null : tierStatus(s)[ws]));
  return (
    <div className="status-row">
      {tier && <span className={`stat-pill ${tier.active ? 'bad' : ''}`} title={tier.reason}><span className="d" />{tier.active ? 'Tier active' : 'Standby'} · {tier.reason}</span>}
      <MonitorPill />
      <AiPill />
      <span className={`stat-pill ${audit.intact ? '' : 'bad'}`}><span className="d" />Ledger {audit.intact ? 'intact' : 'TAMPERED'}</span>
    </div>
  );
}

function IntegrityBanner({ ws }: { ws: Workspace }) {
  const audit = useStore((s) => s.audit);
  const go = useStore((s) => s.go);
  const enter = useStore((s) => s.enter);
  const view = useStore((s) => s.view);
  if (audit.intact) return null;
  return (
    <div className="integrity-banner" role="alert">
      <span className="pill sev-CRITICAL">Integrity</span>
      <span className="grow">Audit ledger verification failed at block <b>#{audit.brokenAt}</b>. A stored record no longer matches its SHA-256 hash.</span>
      {ws === 'admin' && view === 'ledger' ? null : ws === 'admin'
        ? <button type="button" className="btn btn-dark btn-sm" onClick={() => go('ledger')}>Open audit ledger</button>
        : <button type="button" className="btn btn-secondary btn-sm" onClick={() => enter('admin', 'ledger')}>Investigate as administrator</button>}
    </div>
  );
}

export default function App() {
  const ws = useStore((s) => s.workspace);
  const view = useStore((s) => s.view);

  // Record every click and selection the user makes, like a real SOC's user-activity audit trail.
  useEffect(() => {
    const where = () => { const s = useStore.getState(); return s.workspace ? `${s.workspace}/${s.view}` : 'home'; };
    const label = (el: Element) => (el.getAttribute('aria-label') || el.querySelector('h3, h4, b, .t')?.textContent || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 60);
    const onClick = (e: MouseEvent) => {
      const el = (e.target as Element | null)?.closest('button, a, [role="tab"], [role="option"], [role="radio"], [role="switch"], tr.clickable');
      if (!el) return;
      const text = label(el);
      if (!text) return;
      const disabled = el.getAttribute('aria-disabled') === 'true';
      useStore.getState().track(disabled ? 'clicked (blocked)' : 'clicked', `"${text}" on ${where()}`);
    };
    const onChange = (e: Event) => {
      const t = e.target as HTMLInputElement | HTMLSelectElement;
      if (t.tagName === 'SELECT') useStore.getState().track('changed', `${t.getAttribute('aria-label') || t.name || 'select'} = ${(t as HTMLSelectElement).value} on ${where()}`);
      else if (t.type === 'checkbox' || t.type === 'range') useStore.getState().track('changed', `${t.getAttribute('aria-label') || t.type} = ${t.type === 'checkbox' ? (t as HTMLInputElement).checked : t.value} on ${where()}`);
    };
    document.addEventListener('click', onClick, true);
    document.addEventListener('change', onChange, true);
    return () => { document.removeEventListener('click', onClick, true); document.removeEventListener('change', onChange, true); };
  }, []);

  useEffect(() => {
    const onHash = () => syncFromHash();
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  useEffect(() => {
    const target = ws ? `#${ws}/${view}` : '';
    if (window.location.hash !== target) window.history.replaceState(null, '', target || window.location.pathname);
    window.scrollTo({ top: 0 });
  }, [ws, view]);

  if (!ws) return (<><Landing /><Toasts /></>);
  const Page = PAGES[ws];
  const title = VIEWS[ws].find((v) => v.id === view)?.label ?? '';
  return (
    <div className="app">
      <Sidebar ws={ws} />
      <div className="main">
        <header className="main-head">
          <div className="main-head-inner">
            <div>
              <div className="crumbs">{WORKSPACE_LABEL[ws]}</div>
              <h1>{title}</h1>
              <p className="small muted" style={{ marginTop: 4 }}>{SUBTITLE[`${ws}/${view}`]}</p>
            </div>
            <StatusRow ws={ws} />
          </div>
        </header>
        <IntegrityBanner ws={ws} />
        <main id="main-panel" className="content" key={`${ws}/${view}`}>
          <Page />
        </main>
      </div>
      <Toasts />
    </div>
  );
}
