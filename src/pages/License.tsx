import { useStore, effectiveKey } from '../store/store';
import { LICENSE, licenseStatus } from '../engine/license';
import { REAL_VS_SIM, LIMITATIONS } from '../data/copy';
import { storageBytes } from '../store/persist';

export default function License() {
  const engineOn = useStore((s) => s.engineOn);
  const settings = useStore((s) => s.settings);
  const usingEnv = useStore((s) => s.usingEnvKey);
  const data = useStore((s) => s.data);
  const audit = useStore((s) => s.audit);
  const st = licenseStatus();
  const hasKey = !!effectiveKey(settings);
  const kb = (storageBytes() / 1024).toFixed(1);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="label">System</div>
          <h1 style={{ marginTop: 10 }}>License &amp; Health</h1>
          <p>What is running, what is stored, and an honest table of what is real in this build and what is simulated.</p>
        </div>
      </div>

      <div className="grid g2">
        <section className="card" aria-labelledby="lic-h">
          <div className="card-title"><h3 id="lic-h">License</h3><span className={`pill ${st.valid ? 'st-executed' : 'sev-CRITICAL'}`}>{st.valid ? 'Valid' : 'Expired'}</span></div>
          <dl className="stack" style={{ margin: 0 }}>
            {[
              ['Tier', LICENSE.tier],
              ['Licensee', LICENSE.licensee],
              ['Host quota', `${LICENSE.hostQuota} hosts`],
              ['Days remaining', `${st.daysRemaining}`],
              ['Signature', LICENSE.signature],
            ].map(([k, v]) => (
              <div key={k} className="row between" style={{ borderBottom: '1px solid var(--line)', paddingBottom: 8 }}><dt className="muted">{k}</dt><dd style={{ margin: 0, fontWeight: 600 }}>{v}</dd></div>
            ))}
          </dl>
          <p className="small muted" style={{ marginTop: 14 }}>⚠ This license is simulated. The JSON structure and expiry check are real; the signature is a demonstration value.</p>
        </section>

        <section className="card" aria-labelledby="health-h">
          <div className="card-title"><h3 id="health-h">Health</h3><span className={`pill ${engineOn ? 'st-executed' : 'st-dismissed'}`}>Engine {engineOn ? 'on' : 'off'}</span></div>
          <div className="grid g2">
            {[
              ['AI provider', hasKey ? `Gemini · ${settings.model}` : 'Heuristic (local)'],
              ['Gemini key present', hasKey ? (usingEnv ? 'Yes (build env)' : 'Yes') : 'No'],
              ['Storage used', `${kb} KB (localStorage)`],
              ['Events stored', `${data.events.length} / 2000 cap`],
              ['Alerts', `${data.alerts.length}`],
              ['Cases', `${data.cases.length}`],
              ['Audit blocks', `${data.audit.length}`],
              ['Audit chain', audit.intact ? 'Intact ✓' : `TAMPERED (#${audit.brokenAt})`],
            ].map(([k, v]) => (
              <div key={k} style={{ background: 'var(--bg)', borderRadius: 14, padding: '12px 14px' }}>
                <div className="label">{k}</div>
                <div style={{ fontWeight: 600, marginTop: 4, color: k === 'Audit chain' && !audit.intact ? 'var(--coral-d)' : undefined }}>{v}</div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="card" aria-labelledby="rvs-h">
        <div className="card-title"><div><div className="label">Honesty table</div><h3 id="rvs-h" style={{ marginTop: 6 }}>Real vs Simulated</h3></div></div>
        <div className="table-wrap">
          <table className="tbl">
            <caption className="sr-only">What is real and what is simulated in this build</caption>
            <thead><tr><th>Feature</th><th>REAL in this build</th><th>SIMULATED</th></tr></thead>
            <tbody>{REAL_VS_SIM.map((r) => (
              <tr key={r.feature}><td><b>{r.feature}</b></td><td>{r.real}</td><td className={r.sim === 'None' ? 'muted' : ''}>{r.sim}</td></tr>
            ))}</tbody>
          </table>
        </div>
      </section>

      <section className="card" aria-labelledby="lim-h">
        <div className="card-title"><div><div className="label">Known limitations</div><h3 id="lim-h" style={{ marginTop: 6 }}>What Riskbyte does not do</h3></div></div>
        <ol className="steps">{LIMITATIONS.map((l) => <li key={l}>{l}</li>)}</ol>
      </section>
    </div>
  );
}
