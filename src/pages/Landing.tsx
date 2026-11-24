import { useStore, type Workspace } from '../store/store';
import { Footer } from '../components/Footer';

const TIERS: { ws: Workspace; n: string; icon: string; title: string; desc: string; items: string[]; cta: string }[] = [
  {
    ws: 'analyst', n: 'TIER 1', icon: '⚑', title: 'Security Analyst',
    desc: 'Work the alert queue. See what the AI agent found and decide on its recommendations.',
    items: ['Approval queue', 'Alert investigation & evidence', 'Incidents', 'Agent activity log'],
    cta: 'Open analyst console →',
  },
  {
    ws: 'admin', n: 'TIER 2', icon: '⚙', title: 'Administrator',
    desc: 'Run the platform: organizations, agent autonomy, detection content and the audit ledger.',
    items: ['Onboard organizations', 'AI provider & approval policy', 'Rules and threat intel', 'Ledger integrity'],
    cta: 'Open admin console →',
  },
  {
    ws: 'ingest', n: 'TIER 3', icon: '⇪', title: 'Telemetry Ingestion',
    desc: 'Monitor collectors and the event pipeline. Push logs into Riskbyte through the API.',
    items: ['Source health per organization', 'Live event stream', 'Send events (REST API)', 'Pipeline console'],
    cta: 'Open ingestion console →',
  },
  {
    ws: 'demo', n: 'SIMULATOR', icon: '⚡', title: 'Demo',
    desc: 'Launch simulated attacks against an organization, then watch the agent respond in the other consoles.',
    items: ['10 attack techniques', 'Choose the target organization', 'Continuous attack mode'],
    cta: 'Open attack simulator →',
  },
];

export default function Landing() {
  const enter = useStore((s) => s.enter);
  const orgs = useStore((s) => s.data.orgs);
  const pending = useStore((s) => s.data.alerts.filter((a) => a.status === 'triaged' || a.status === 'new').length);
  const audit = useStore((s) => s.audit);
  return (
    <div className="landing">
      <main className="landing-main">
        <header className="landing-head fade-in">
          <div>
            <div className="label">AI-driven Security Operations Center</div>
            <h1 style={{ marginTop: 12 }}><span className="dot" aria-hidden />Riskbyte</h1>
            <p>An autonomous SOC agent detects, investigates and recommends. Humans approve. Every action is written to a tamper-evident ledger.</p>
          </div>
          <div className="landing-strip" aria-label="Platform status">
            <span className="stat-pill live"><span className="d" />Agent online</span>
            <span className="stat-pill"><span className="d" />{orgs.length} organizations monitored</span>
            <span className={`stat-pill ${pending ? 'warn' : ''}`}><span className="d" />{pending} awaiting approval</span>
            <span className={`stat-pill ${audit.intact ? '' : 'bad'}`}><span className="d" />Ledger {audit.intact ? 'intact' : 'TAMPERED'}</span>
          </div>
        </header>
        <section aria-label="Choose a workspace" className="tier-grid">
          {TIERS.map((t, i) => (
            <button key={t.ws} type="button" className={`card clickable lift tier fade-in ${t.ws === 'demo' ? 'demo' : ''}`} style={{ animationDelay: `${60 * i}ms` }} onClick={() => enter(t.ws)}>
              <span className="tier-n">{t.n}</span>
              <span className="ic" aria-hidden>{t.icon}</span>
              <h3>{t.title}</h3>
              <p style={{ fontSize: 14.5 }} className={t.ws === 'demo' ? '' : 'muted'}>{t.desc}</p>
              <ul>{t.items.map((x) => <li key={x}>{x}</li>)}</ul>
              <span className="go">{t.cta}</span>
            </button>
          ))}
        </section>
      </main>
      <Footer />
    </div>
  );
}
