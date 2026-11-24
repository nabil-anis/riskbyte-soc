import { useStore } from '../store/store';
import type { Role } from '../engine/types';
import { Footer } from '../components/Footer';

const ROLES: { role: Role; icon: string; title: string; desc: string; can: string[]; cannot?: string[] }[] = [
  {
    role: 'analyst', icon: '🎯', title: 'Security Analyst Dashboard',
    desc: 'Investigate alerts, read the AI\'s reasoning, and decide what happens.',
    can: ['Investigate alerts and cases', 'Approve or dismiss containment', 'Run attacks in the Demo lab'],
    cannot: ['Tamper demo and data reset'],
  },
  {
    role: 'admin', icon: '🛡️', title: 'Administrator',
    desc: 'Everything an analyst can do, plus the forensic audit tools.',
    can: ['Everything the analyst can do', 'Verify the SHA-256 audit chain', 'Tamper demo, repair and reset'],
  },
  {
    role: 'ingest', icon: '📡', title: 'Telemetry Ingest',
    desc: 'A log shipper account: it can send events and nothing else.',
    can: ['Send log batches to POST /api/ingest', 'View License & Health'],
    cannot: ['Approve or dismiss (403 Forbidden)'],
  },
];

export default function Login() {
  const login = useStore((s) => s.login);
  return (
    <div className="login">
      <main className="login-main">
        <section className="hero fade-in">
          <div className="label">Mini Security Operations Center</div>
          <h1 style={{ marginTop: 14 }}><span className="dot" aria-hidden />Riskbyte</h1>
          <p className="lead">A mini SOC that investigates, explains, and waits for your approval.</p>
          <div className="flow" aria-label="How Riskbyte works">
            {['1 · Logs arrive', '2 · Rules detect', '3 · Intel confirms', '4 · AI explains', '5 · You approve', '6 · Ledger records'].map((s) => (
              <span key={s} className="pill chip">{s}</span>
            ))}
          </div>
        </section>
        <section aria-label="Choose a role" className="stack-lg">
          <div className="label">Choose how you sign in</div>
          <div className="grid g3">
            {ROLES.map((r, i) => (
              <button key={r.role} type="button" className="card clickable lift role-card fade-in" style={{ animationDelay: `${80 * i}ms` }} onClick={() => login(r.role)}>
                <span className="icon" aria-hidden>{r.icon}</span>
                <h3>{r.title}</h3>
                <p className="muted">{r.desc}</p>
                <ul>
                  {r.can.map((c) => <li key={c}>{c}</li>)}
                  {r.cannot?.map((c) => <li key={c} className="no">{c}</li>)}
                </ul>
                <span className="go">Enter as {r.title.split(' ')[0] === 'Security' ? 'Analyst' : r.title} →</span>
              </button>
            ))}
          </div>
          <p className="small muted">No password needed: this is a classroom simulation with simulated role tokens. Everything runs in your browser.</p>
        </section>
      </main>
      <Footer />
    </div>
  );
}
