import { useStore, tierStatus, type Workspace } from '../store/store';
import { Footer } from '../components/Footer';
import { LiveLog, useMonitorStats, AiPill } from '../components/Live';
import { RULES } from '../data/rules';

const TIERS: { ws: Workspace; n: string; icon: string; title: string; desc: string; items: string[]; cta: string }[] = [
  {
    ws: 'analyst', n: 'TIER 1', icon: '⚑', title: 'Security Analyst',
    desc: 'Called in when the agent needs a human decision on a containment action.',
    items: ['Approval queue', 'Alert investigation & evidence', 'Incidents', 'Agent activity log'],
    cta: 'Open analyst console →',
  },
  {
    ws: 'admin', n: 'TIER 2', icon: '⚙', title: 'Administrator',
    desc: 'Called in for critical incidents and platform integrity problems.',
    items: ['Organizations', 'AI provider & approval policy', 'Rules and threat intel', 'Audit ledger'],
    cta: 'Open admin console →',
  },
  {
    ws: 'ingest', n: 'TIER 3', icon: '⇪', title: 'Telemetry Ingestion',
    desc: 'Called in when hostile or malformed telemetry shows up in the pipeline.',
    items: ['Collector health per organization', 'Live event stream', 'Send events (REST API)', 'Pipeline console'],
    cta: 'Open ingestion console →',
  },
  {
    ws: 'demo', n: 'SIMULATOR', icon: '⚡', title: 'Demo',
    desc: 'Launch simulated attacks against an organization and watch the tiers wake up.',
    items: ['10 attack techniques + insider tampering', 'Choose the target organization', 'Continuous attack mode'],
    cta: 'Open attack simulator →',
  },
];

export default function Landing() {
  const enter = useStore((s) => s.enter);
  const orgs = useStore((s) => s.data.orgs);
  const status = useStore((s) => tierStatus(s));
  const { perMin, uptime, lastScan, total } = useMonitorStats();
  const anyActive = status.analyst.active || status.admin.active || status.ingest.active;

  return (
    <div className="landing">
      <main className="landing-main">
        <header className="landing-head fade-in">
          <div>
            <div className="label">AI-driven Security Operations Center</div>
            <h1 style={{ marginTop: 12 }}><span className="dot" aria-hidden />Riskbyte</h1>
            <p>The agent watches every organization around the clock. People are only called in when something is wrong.</p>
          </div>
        </header>

        <section className={`ops-board ${anyActive ? 'alert' : 'calm'}`} aria-label="Live operations">
          <div className="ops-state">
            <div className="label">{anyActive ? 'Escalation in progress' : 'Continuous monitoring · 24/7'}</div>
            <div className="ops-title"><span className="big-dot" aria-hidden />{anyActive ? 'Attention required' : 'All clear'}</div>
            <p className="ops-sub">{anyActive
              ? 'The agent found something it cannot resolve alone. The responsible tier has been activated below.'
              : `Detection is running on live telemetry from ${orgs.length} organizations. No tier needs to act.`}</p>
            <div className="ops-metrics">
              <div><span className="label">Uptime</span><b className="mono">{uptime}</b></div>
              <div><span className="label">Events / min</span><b>{perMin}</b></div>
              <div><span className="label">Events scanned</span><b>{total}</b></div>
              <div><span className="label">Rules active</span><b>{RULES.length}</b></div>
              <div><span className="label">Last scan</span><b>{lastScan === null ? '—' : `${lastScan}s ago`}</b></div>
            </div>
            <div className="row" style={{ marginTop: 14 }}><AiPill /></div>
          </div>
          <LiveLog lines={40} height={260} title="Live pipeline" />
        </section>

        <section aria-label="Choose a workspace" className="tier-grid">
          {TIERS.map((t, i) => {
            const st = t.ws === 'demo' ? null : status[t.ws];
            return (
              <button key={t.ws} type="button" className={`card clickable lift tier fade-in ${t.ws === 'demo' ? 'demo' : ''} ${st?.active ? 'active' : ''}`} style={{ animationDelay: `${60 * i}ms` }} onClick={() => enter(t.ws)}>
                <div className="row between">
                  <span className="tier-n">{t.n}</span>
                  {st && <span className={`tier-state ${st.active ? 'on' : ''}`}><span className="d" aria-hidden />{st.active ? 'ACTIVE' : 'STANDBY'}</span>}
                </div>
                <span className="ic" aria-hidden>{t.icon}</span>
                <h3>{t.title}</h3>
                {st && <p className={`tier-reason ${st.active ? 'on' : ''}`}>{st.reason}</p>}
                <p style={{ fontSize: 14 }} className={t.ws === 'demo' ? '' : 'muted'}>{t.desc}</p>
                <ul>{t.items.map((x) => <li key={x}>{x}</li>)}</ul>
                <span className="go">{t.cta}</span>
              </button>
            );
          })}
        </section>
      </main>
      <Footer />
    </div>
  );
}
