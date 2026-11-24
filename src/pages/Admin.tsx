import { useEffect, useState } from 'react';
import { useStore, effectiveKey } from '../store/store';
import type { Action, Rule } from '../engine/types';
import { RULES } from '../data/rules';
import { INDICATORS } from '../data/indicators';
import { ACTION_LABEL, ACTION_PLAIN, LIMITATIONS } from '../data/copy';
import { ENV_KEY, storageBytes } from '../store/persist';
import { testConnection } from '../engine/gemini';
import { LICENSE, licenseStatus } from '../engine/license';
import { ROUTES } from '../engine/api';
import { TOKENS } from '../engine/auth';
import { Button, ClientBadge, ConfirmModal, Modal, SeverityBadge, copy, fmtDateTime } from '../components/ui';
import { Bars } from './Analyst';

export default function AdminWorkspace() {
  const view = useStore((s) => s.view);
  switch (view) {
    case 'orgs': return <Orgs />;
    case 'agent': return <AgentSettings />;
    case 'rules': return <Rules />;
    case 'intel': return <Intel />;
    case 'ledger': return <Ledger />;
    case 'system': return <System />;
    default: return <Overview />;
  }
}

function Overview() {
  const data = useStore((s) => s.data);
  const audit = useStore((s) => s.audit);
  const settings = useStore((s) => s.settings);
  const go = useStore((s) => s.go);
  const avg = data.counters.batches ? (data.counters.totalMs / data.counters.batches).toFixed(1) : '0.0';
  const autoActions = Object.values(settings.policy.modes).filter((m) => m === 'auto').length;
  return (
    <>
      <section className="kpis">
        <div className="kpi"><span className="label">Organizations</span><span className="v">{data.orgs.length}</span><span className="s">monitored tenants</span></div>
        <div className="kpi"><span className="label">Telemetry ingested</span><span className="v">{data.counters.totalIngested}</span><span className="s">{data.counters.batches} batches</span></div>
        <div className="kpi"><span className="label">Open incidents</span><span className="v">{data.cases.filter((c) => c.status === 'open').length}</span><span className="s">{data.alerts.length} alerts total</span></div>
        <div className="kpi"><span className="label">Pipeline latency</span><span className="v">{avg}<span style={{ fontSize: '.5em' }}> ms</span></span><span className="s">avg per batch, excl. AI</span></div>
        <div className="kpi"><span className="label">AI provider</span><span className="v sm">{effectiveKey(settings) ? 'Gemini' : 'Heuristic'}</span><span className="s">{effectiveKey(settings) ? settings.model : 'no API key configured'}</span></div>
        <div className={`kpi ${audit.intact ? '' : 'hot'}`}><span className="label">Ledger integrity</span><span className={`v sm ${audit.intact ? 'ok' : 'coral'}`}>{audit.intact ? 'Intact ✓' : 'TAMPERED'}</span><span className="s">{audit.intact ? `${data.audit.length} blocks verified` : `broken at #${audit.brokenAt}`}</span></div>
      </section>
      <div className="cols-2e">
        <section className="panel">
          <div className="panel-head"><h3>Agent autonomy</h3><div className="right"><Button size="sm" variant="secondary" onClick={() => go('agent')}>Configure</Button></div></div>
          <div className="panel-body stack">
            <p>{autoActions === 0 ? 'Human-in-the-loop: every containment action needs analyst approval.' : `${autoActions} of 4 action types may be auto-executed when the verdict is MALICIOUS at ≥ ${settings.policy.minConfidence}% confidence.`}</p>
            <div className="row">{(Object.keys(settings.policy.modes) as Action[]).map((a) => (
              <span key={a} className={`pill ${settings.policy.modes[a] === 'auto' ? 'st-executed' : 'st-triaged'}`}>{a}: {settings.policy.modes[a] === 'auto' ? 'auto' : 'approval'}</span>
            ))}</div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head"><h3>Telemetry by organization</h3><div className="right"><Button size="sm" variant="secondary" onClick={() => go('orgs')}>Manage</Button></div></div>
          <div className="panel-body"><Bars rows={data.orgs.map((o) => ({ label: o.name, n: data.events.filter((e) => e.client === o.id).length }))} /></div>
        </section>
      </div>
    </>
  );
}

function Orgs() {
  const orgs = useStore((s) => s.data.orgs);
  const data = useStore((s) => s.data);
  const addOrg = useStore((s) => s.addOrg);
  const removeOrg = useStore((s) => s.removeOrg);
  const [name, setName] = useState('');
  const [sector, setSector] = useState('');
  const [desc, setDesc] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<string | null>(null);
  const submit = async () => {
    if (!name.trim()) return;
    setBusy(true);
    const ok = await addOrg({ name, sector, description: desc });
    setBusy(false);
    if (ok) { setName(''); setSector(''); setDesc(''); }
  };
  const target = orgs.find((o) => o.id === confirm);
  return (
    <div className="cols-2">
      <section className="panel">
        <div className="panel-head"><h3>Monitored organizations</h3><div className="right"><span className="pill chip">{orgs.length}</span></div></div>
        <div className="table-wrap">
          <table className="tbl">
            <caption className="sr-only">Organizations</caption>
            <thead><tr><th>Organization</th><th>ID</th><th>Sector</th><th>Events</th><th>Open alerts</th><th>Onboarded</th><th /></tr></thead>
            <tbody>{orgs.map((o) => (
              <tr key={o.id}>
                <td><b>{o.name}</b>{o.description && <div className="small muted">{o.description}</div>}</td>
                <td className="mono nowrap">{o.id}</td>
                <td>{o.sector}</td>
                <td>{data.events.filter((e) => e.client === o.id).length}</td>
                <td>{data.alerts.filter((a) => a.client === o.id && (a.status === 'new' || a.status === 'triaged')).length}</td>
                <td className="nowrap small">{o.builtIn ? 'built-in' : fmtDateTime(o.createdAt)}</td>
                <td><Button size="sm" variant="neutral" onClick={() => setConfirm(o.id)} disabledReason={orgs.length <= 1 ? 'At least one organization is required' : null}>Offboard</Button></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head"><h3>Onboard an organization</h3></div>
        <form className="panel-body stack" onSubmit={(e) => { e.preventDefault(); submit(); }}>
          <label className="field"><span>Name</span><input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Aga Khan University Hospital" required /></label>
          <label className="field"><span>Sector</span><input className="input" value={sector} onChange={(e) => setSector(e.target.value)} placeholder="e.g. Healthcare" /></label>
          <label className="field"><span>Description <span className="muted">(optional)</span></span><input className="input" value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Key systems and assets" /></label>
          <p className="small muted">The organization gets an ID that log shippers put in each event’s <code>client</code> field. It immediately appears in every console and in the attack simulator.</p>
          <div><Button type="submit" busy={busy} disabledReason={!name.trim() ? 'Enter a name' : null}>Onboard organization</Button></div>
        </form>
      </section>
      <ConfirmModal open={!!confirm} onClose={() => setConfirm(null)} title={`Offboard ${target?.name ?? ''}?`} confirmLabel="Offboard"
        onConfirm={() => confirm && removeOrg(confirm)} body="New telemetry for this organization will be rejected. Existing alerts, incidents and ledger records are kept. The action is written to the audit ledger." />
    </div>
  );
}

function AgentSettings() {
  const settings = useStore((s) => s.settings);
  const update = useStore((s) => s.updateSettings);
  const setPolicy = useStore((s) => s.setPolicy);
  const toast = useStore((s) => s.toast);
  const [key, setKey] = useState(settings.apiKey);
  const [model, setModel] = useState(settings.model);
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => { setKey(settings.apiKey); setModel(settings.model); }, [settings.apiKey, settings.model]);

  const save = () => {
    update({ apiKey: key.trim(), model: model.trim() || 'gemini-2.5-flash' });
    useStore.getState().log('INFO', `AI provider set to ${key.trim() || ENV_KEY ? `gemini (${model.trim() || 'gemini-2.5-flash'})` : 'heuristic (no API key set)'}`);
    toast(key.trim() ? 'Saved. New alerts are triaged by Gemini.' : 'Saved. The agent uses the local heuristic model.', 'ok');
  };
  const test = async () => {
    setTesting(true); setResult(null);
    const r = await testConnection(key.trim() || ENV_KEY, model.trim() || 'gemini-2.5-flash');
    setTesting(false);
    setResult(r.ok ? { ok: true, text: `Connected · ${model} replied in ${r.ms} ms` } : { ok: false, text: `Failed after ${r.ms} ms: ${r.error}` });
  };
  const usingEnv = !key.trim() && !!ENV_KEY;

  return (
    <div className="cols-2e">
      <section className="panel">
        <div className="panel-head"><h3>AI provider</h3><div className="right"><span className={`pill ${effectiveKey(settings) ? 'st-executed' : 'sev-MEDIUM'}`}>{effectiveKey(settings) ? 'Gemini' : 'Heuristic'}</span></div></div>
        <div className="panel-body stack">
          <label className="field">
            <span>Google Gemini API key</span>
            <div className="row" style={{ flexWrap: 'nowrap' }}>
              <input className="input mono" type={show ? 'text' : 'password'} value={key} onChange={(e) => setKey(e.target.value)} placeholder="AIza…" autoComplete="off" spellCheck={false} />
              <Button variant="secondary" size="sm" onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'}</Button>
            </div>
            <span className="help">{usingEnv ? 'Using key from build environment. ' : ''}Stored in this browser only; never logged or sent anywhere except Google’s API. Leave empty to use the local heuristic model.</span>
          </label>
          <label className="field">
            <span>Model</span>
            <input className="input mono" value={model} onChange={(e) => setModel(e.target.value)} placeholder="gemini-2.5-flash" spellCheck={false} />
            <span className="help">If you get a 404, try another Gemini model name.</span>
          </label>
          <div className="row">
            <Button onClick={save}>Save</Button>
            <Button variant="secondary" onClick={test} busy={testing} disabledReason={!key.trim() && !ENV_KEY ? 'Paste a key first' : null}>Test connection</Button>
          </div>
          {result && <div role="status" className={`banner ${result.ok ? '' : 'bad'}`} style={{ borderLeftColor: result.ok ? 'var(--ok)' : undefined }}>{result.text}</div>}
          <p className="small muted">Before evidence leaves the browser, IPs, usernames, hostnames and the organization name are replaced with tokens like <code>[REDACTED_IP_1]</code> and mapped back locally. If Gemini fails or times out (12 s), the agent falls back to the heuristic model and says so on the alert.</p>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head"><h3>Approval policy</h3></div>
        <div className="panel-body stack">
          <p className="small muted">Choose which containment actions the agent may execute by itself. Everything else waits for a human.</p>
          <div className="table-wrap">
            <table className="tbl">
              <caption className="sr-only">Approval policy per action</caption>
              <thead><tr><th>Action</th><th>Effect</th><th>Mode</th></tr></thead>
              <tbody>{(Object.keys(settings.policy.modes) as Action[]).map((a) => (
                <tr key={a}>
                  <td className="mono nowrap">{a}</td>
                  <td className="small">{ACTION_PLAIN[a]}</td>
                  <td>
                    <div className="seg" role="tablist" aria-label={`${ACTION_LABEL[a]} mode`}>
                      <button type="button" role="tab" aria-selected={settings.policy.modes[a] === 'approve'} onClick={() => setPolicy({ modes: { [a]: 'approve' } as Record<Action, 'approve'> })}>Human approval</button>
                      <button type="button" role="tab" aria-selected={settings.policy.modes[a] === 'auto'} onClick={() => setPolicy({ modes: { [a]: 'auto' } as Record<Action, 'auto'> })}>Auto</button>
                    </div>
                  </td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <label className="field">
            <span>Auto-execute threshold: MALICIOUS at ≥ {settings.policy.minConfidence}% confidence</span>
            <input className="range" type="range" min={50} max={99} value={settings.policy.minConfidence} onChange={(e) => setPolicy({ minConfidence: Number(e.target.value) })} />
          </label>
          <p className="small muted">Auto-executed actions are recorded as <code>ai:riskbyte-agent</code> in the ledger. Execution is dry-run in this build.</p>
        </div>
      </section>
    </div>
  );
}

function Rules() {
  const [rule, setRule] = useState<Rule | null>(null);
  const alerts = useStore((s) => s.data.alerts);
  return (
    <section className="panel">
      <div className="panel-head"><h3>Active rules</h3><div className="right"><span className="pill chip">{RULES.length} enabled</span></div></div>
      <div className="table-wrap">
        <table className="tbl">
          <caption className="sr-only">Detection rules</caption>
          <thead><tr><th>ID</th><th>Rule</th><th>MITRE</th><th>Severity</th><th>Response</th><th>Hits</th></tr></thead>
          <tbody>{RULES.map((r) => (
            <tr key={r.id} className="clickable" tabIndex={0} onClick={() => setRule(r)} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setRule(r))}>
              <td className="mono nowrap">{r.id}</td>
              <td><b>{r.title}</b><div className="small muted">{r.description}</div></td>
              <td className="mono">{r.mitre}</td>
              <td><SeverityBadge sev={r.severity} /></td>
              <td className="mono nowrap">{r.action}</td>
              <td>{alerts.filter((a) => a.ruleId === r.id).length}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <Modal open={!!rule} onClose={() => setRule(null)} kind="drawer" label={`Rule ${rule?.id}`}
        title={rule && <div><div className="label mono">{rule.id} · {rule.mitre}</div><h3 style={{ marginTop: 6 }}>{rule.title}</h3></div>}>
        {rule && (
          <div className="stack-lg">
            <div className="row"><SeverityBadge sev={rule.severity} /><span className="pill chip">Response: {rule.action}</span></div>
            <p>{rule.description}</p>
            <pre className="yaml" aria-label="Sigma YAML">{rule.yaml}</pre>
          </div>
        )}
      </Modal>
    </section>
  );
}

function Intel() {
  const alerts = useStore((s) => s.data.alerts);
  return (
    <section className="panel">
      <div className="panel-head"><h3>Indicators</h3><div className="right"><span className="pill chip">{INDICATORS.length}</span></div></div>
      <div className="table-wrap">
        <table className="tbl">
          <caption className="sr-only">Threat intelligence indicators</caption>
          <thead><tr><th>Indicator</th><th>Type</th><th>Category</th><th>Confidence</th><th>Sightings</th><th>Note</th></tr></thead>
          <tbody>{INDICATORS.map((i) => (
            <tr key={i.value}>
              <td className="mono nowrap">{i.value}</td><td>{i.type}</td><td>{i.category}</td><td>{Math.round(i.confidence * 100)}%</td>
              <td>{alerts.filter((a) => a.intelHits.some((h) => h.value === i.value)).length}</td><td className="small">{i.note}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <div className="panel-body small muted">IP indicators use RFC 5737 documentation ranges; 1.2.3.4 is a common placeholder used as a stand-in.</div>
    </section>
  );
}

function Ledger() {
  const blocks = useStore((s) => s.data.audit);
  const audit = useStore((s) => s.audit);
  const verify = useStore((s) => s.verifyAudit);
  const repair = useStore((s) => s.repair);
  const toast = useStore((s) => s.toast);
  const [open, setOpen] = useState<Record<number, boolean>>({});
  const [busy, setBusy] = useState<string | null>(null);
  useEffect(() => { verify(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(blocks, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `riskbyte-ledger-${new Date().toISOString().slice(0, 10)}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <section className="panel">
        <div className="panel-body row">
          <span className={`chain-badge ${audit.intact ? 'ok' : 'bad'}`} role="status">{audit.intact ? `Hash chain intact · ${blocks.length} blocks · SHA-256` : `Hash chain TAMPERED at block #${audit.brokenAt}`}</span>
          <span className="grow" />
          <Button variant="secondary" busy={busy === 'v'} onClick={async () => { setBusy('v'); const s = await verify(); setBusy(null); toast(s.intact ? `Verified ${s.blocks} blocks` : `Verification failed at block #${s.brokenAt}`, s.intact ? 'ok' : 'error'); }}>Verify now</Button>
          <Button busy={busy === 'r'} disabledReason={audit.intact ? 'Chain is intact' : null} onClick={async () => { setBusy('r'); await repair(); setBusy(null); }}>Rebuild chain</Button>
          <Button variant="secondary" onClick={exportJson}>Export JSON</Button>
        </div>
        <div className="panel-body small muted" style={{ borderTop: '1px solid var(--line)' }}>Last verified {fmtDateTime(audit.checkedAt)} · <code>hash = SHA256(prevHash + ts + actor + kind + detail)</code></div>
        {!audit.intact && <div className="panel-body small" style={{ borderTop: '1px solid var(--line)' }}>Rebuilding recomputes hashes from the broken block onward and appends a <code>ledger.repaired</code> block signed by you, so the repair itself stays on record. The ledger is tamper-evident, not tamper-proof: in production the latest hash would also be anchored outside this system.</div>}
      </section>
      <section className="panel">
        <div className="table-wrap tall">
          <table className="tbl">
            <caption className="sr-only">Audit blocks, newest first</caption>
            <thead><tr><th>#</th><th>Time</th><th>Organization</th><th>Actor</th><th>Event</th><th>Alert</th><th>Detail</th><th>Hash</th></tr></thead>
            <tbody>{[...blocks].reverse().map((b) => {
              const broken = !audit.intact && b.index === audit.brokenAt;
              return (
                <tr key={b.index} className={broken ? 'broken' : ''}>
                  <td className="mono">{b.index}{broken && <div><span className="pill sev-CRITICAL" style={{ marginTop: 4 }}>broken</span></div>}</td>
                  <td className="nowrap small">{fmtDateTime(b.ts)}</td>
                  <td><ClientBadge client={b.client} /></td>
                  <td className="mono small">{b.actor}</td>
                  <td className="mono small nowrap">{b.kind}</td>
                  <td className="mono small">{b.alertId ? <button type="button" className="lnk" onClick={() => { useStore.getState().enter('analyst', 'alerts'); useStore.getState().set({ selectedAlertId: b.alertId! }); }}>{b.alertId}</button> : '-'}</td>
                  <td className="small" style={{ minWidth: 220 }}>{b.detail}</td>
                  <td>
                    <div className="hash-cell">
                      <div className="row" style={{ gap: 6 }}>
                        <code>{b.hash.slice(0, 10)}</code>
                        <button type="button" className="link-btn" onClick={() => copy(b.hash).then(() => toast('Hash copied'))}>copy</button>
                        <button type="button" className="link-btn" aria-expanded={!!open[b.index]} onClick={() => setOpen((o) => ({ ...o, [b.index]: !o[b.index] }))}>{open[b.index] ? 'hide' : 'full'}</button>
                      </div>
                      {open[b.index] && <div className="full"><div><b>hash</b> {b.hash}</div><div><b>prev</b> {b.prevHash}</div></div>}
                    </div>
                  </td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function System() {
  const data = useStore((s) => s.data);
  const resetData = useStore((s) => s.resetData);
  const clearAllData = useStore((s) => s.clearAllData);
  const [confirm, setConfirm] = useState<'reset' | 'wipe' | null>(null);
  const st = licenseStatus();
  return (
    <>
      <div className="cols-2e">
        <section className="panel">
          <div className="panel-head"><h3>License</h3><div className="right"><span className={`pill ${st.valid ? 'st-executed' : 'sev-CRITICAL'}`}>{st.valid ? 'Valid' : 'Expired'}</span></div></div>
          <div className="panel-body stack">
            {[['Tier', LICENSE.tier], ['Host quota', `${LICENSE.hostQuota} hosts`], ['Days remaining', `${st.daysRemaining}`], ['Signature', LICENSE.signature]].map(([k, v]) => (
              <div key={k} className="row between" style={{ borderBottom: '1px solid var(--line)', paddingBottom: 8 }}><span className="muted">{k}</span><b>{v}</b></div>
            ))}
            <p className="small muted">Development license; the signature is a demonstration value.</p>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head"><h3>Storage</h3></div>
          <div className="panel-body stack">
            {[['Backend', 'Browser localStorage'], ['Used', `${(storageBytes() / 1024).toFixed(1)} KB`], ['Events retained', `${data.events.length} / 2000`], ['Alerts', `${data.alerts.length}`], ['Incidents', `${data.cases.length}`], ['Ledger blocks', `${data.audit.length}`]].map(([k, v]) => (
              <div key={k} className="row between" style={{ borderBottom: '1px solid var(--line)', paddingBottom: 8 }}><span className="muted">{k}</span><b>{v}</b></div>
            ))}
          </div>
        </section>
      </div>
      <section className="panel">
        <div className="panel-head"><h3>API</h3><div className="right">{Object.entries(TOKENS).map(([r, t]) => <span key={r} className="pill chip mono">{r}: {t}</span>)}</div></div>
        <div className="table-wrap">
          <table className="tbl">
            <caption className="sr-only">API routes</caption>
            <thead><tr><th>Route</th><th>ingest</th><th>analyst</th><th>admin</th></tr></thead>
            <tbody>{ROUTES.map((r) => (
              <tr key={r.method + r.pattern}><td className="mono">{r.method} {r.pattern}</td>{(['ingest', 'analyst', 'admin'] as const).map((role) => <td key={role}>{r.roles.includes(role) ? '✓' : <span className="muted">403</span>}</td>)}</tr>
            ))}</tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head"><h3>Known limitations</h3></div>
        <div className="panel-body"><ol className="steps small">{LIMITATIONS.map((l) => <li key={l}>{l}</li>)}</ol></div>
      </section>
      <section className="panel">
        <div className="panel-head"><h3>Data management</h3></div>
        <div className="panel-body row">
          <Button variant="secondary" onClick={() => setConfirm('reset')}>Clear telemetry, alerts &amp; ledger</Button>
          <Button variant="neutral" onClick={() => setConfirm('wipe')}>Factory reset</Button>
          <span className="small muted">Clearing keeps organizations and settings. Factory reset removes everything stored in this browser.</span>
        </div>
      </section>
      <ConfirmModal open={confirm === 'reset'} onClose={() => setConfirm(null)} title="Clear platform data?" confirmLabel="Clear" onConfirm={resetData}
        body="Events, alerts, incidents and the audit ledger are removed. A new ledger starts with a genesis block and a system.reset block." />
      <ConfirmModal open={confirm === 'wipe'} onClose={() => setConfirm(null)} title="Factory reset?" confirmLabel="Reset everything" onConfirm={clearAllData}
        body="Removes all data, organizations you added, settings and the API key from this browser, then reloads." />
    </>
  );
}
