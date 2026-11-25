import { useEffect, useMemo, useState } from 'react';
import { useStore } from '../store/store';
import type { Role } from '../engine/types';
import { INDICATORS } from '../data/indicators';
import { liveIntel } from '../engine/intel';
import { LICENSE, verifyLicense, type LicenseCheck } from '../engine/license';
import { ACTION_PLAIN } from '../data/copy';
import { Button, ClientBadge, ConfirmModal, EmptyState, fmtDateTime, relTime, useTick } from '../components/ui';

export function Containment() {
  useTick(10000);
  const controls = useStore((s) => s.data.controls ?? []);
  const events = useStore((s) => s.data.events);
  const release = useStore((s) => s.releaseControl);
  const go = useStore((s) => s.enter);
  const [confirm, setConfirm] = useState<string | null>(null);
  const enforcedCount = (value: string) => events.filter((e) => e.meta?.enforced && [e.ip, e.user, e.host].some((v) => v?.toLowerCase() === value)).length;
  const target = controls.find((c) => c.id === confirm);
  return (
    <>
      <section className="kpis">
        {(['block_ip', 'disable_user', 'isolate_host', 'reset_password'] as const).map((k) => (
          <div key={k} className="kpi"><span className="label">{k.replace('_', ' ')}</span><span className="v">{controls.filter((c) => c.kind === k).length}</span><span className="s">active</span></div>
        ))}
        <div className="kpi"><span className="label">Events enforced</span><span className="v">{events.filter((e) => e.meta?.enforced).length}</span><span className="s">blocked / denied / quarantined</span></div>
      </section>
      <section className="panel">
        <div className="panel-head"><h3>Active controls</h3><div className="right"><span className="small muted">Approved containment is enforced on every later event and on console sign-ins.</span></div></div>
        {controls.length === 0 ? <EmptyState icon="⛨" title="Nothing is contained">When an analyst approves a recommendation (or the agent auto-executes one), it shows up here and is enforced immediately.</EmptyState> : (
          <div className="table-wrap">
            <table className="tbl">
              <caption className="sr-only">Active containment controls</caption>
              <thead><tr><th>Control</th><th>Target</th><th>Organization</th><th>Effect</th><th>From alert</th><th>Approved by</th><th>Since</th><th>Hits</th><th /></tr></thead>
              <tbody>{[...controls].reverse().map((c) => (
                <tr key={c.id}>
                  <td className="mono nowrap">{c.kind}</td>
                  <td className="mono">{c.value}</td>
                  <td><ClientBadge client={c.client} /></td>
                  <td className="small">{ACTION_PLAIN[c.kind]}</td>
                  <td className="mono">{c.alertId ? <button type="button" className="lnk" onClick={() => { go('analyst', 'alerts'); useStore.getState().set({ selectedAlertId: c.alertId! }); }}>{c.alertId}</button> : '-'}</td>
                  <td className="mono small">{c.by}</td>
                  <td className="nowrap small">{relTime(c.at)}</td>
                  <td>{enforcedCount(c.value)}</td>
                  <td><Button size="sm" variant="neutral" onClick={() => setConfirm(c.id)}>Release</Button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
      <ConfirmModal open={!!confirm} onClose={() => setConfirm(null)} title={`Release ${target?.kind} ${target?.value}?`} confirmLabel="Release"
        onConfirm={() => confirm && release(confirm)} body="Riskbyte stops enforcing this control immediately. The release is written to the audit ledger." />
    </>
  );
}

export function Access() {
  useTick(1000);
  const accounts = useStore((s) => s.accounts);
  const sessions = useStore((s) => s.sessions);
  const client = useStore((s) => s.client);
  const events = useStore((s) => s.data.events);
  const deleteAccount = useStore((s) => s.deleteAccount);
  const [confirm, setConfirm] = useState<Role | null>(null);
  const authEvents = useMemo(() => events.filter((e) => e.client === 'riskbyte' && /login|logout|password/.test(e.action)).slice(-50).reverse(), [events]);
  const roles: Role[] = ['analyst', 'admin', 'ingest'];
  return (
    <>
      <section className="kpis">
        <div className="kpi"><span className="label">Your address</span><span className="v sm mono" style={{ fontSize: 20 }}>{client?.ip ?? '…'}</span><span className="s">{[client?.city, client?.region, client?.country].filter(Boolean).join(', ') || (client?.source === 'dev-server' ? 'local development' : 'location unavailable')}</span></div>
        <div className="kpi"><span className="label">Accounts</span><span className="v">{Object.keys(accounts).length}/3</span><span className="s">PBKDF2-SHA256 · 150k iterations</span></div>
        <div className="kpi"><span className="label">Active sessions</span><span className="v">{Object.keys(sessions).length}</span><span className="s">8-hour expiry</span></div>
        <div className="kpi"><span className="label">Failed sign-ins</span><span className="v">{events.filter((e) => e.client === 'riskbyte' && e.action === 'login_failed').length}</span><span className="s">5 in 30s from one IP trigger rb-001</span></div>
      </section>
      <section className="panel">
        <div className="panel-head"><h3>Console accounts</h3></div>
        <div className="table-wrap">
          <table className="tbl">
            <caption className="sr-only">Accounts</caption>
            <thead><tr><th>Tier</th><th>Username</th><th>Hash</th><th>Created</th><th>Password changed</th><th>Last sign-in</th><th>Status</th><th>Session</th><th /></tr></thead>
            <tbody>{roles.map((r) => {
              const a = accounts[r];
              const s = sessions[r];
              const locked = a?.lockedUntil && a.lockedUntil > Date.now();
              return (
                <tr key={r}>
                  <td><b>{r}</b></td>
                  <td className="mono">{a?.username ?? <span className="muted">not set up</span>}</td>
                  <td className="mono small">{a ? `${a.algo} · ${a.iterations.toLocaleString()}` : '-'}</td>
                  <td className="small nowrap">{a ? fmtDateTime(a.createdAt) : '-'}</td>
                  <td className="small nowrap">{a ? relTime(a.passwordChangedAt) : '-'}</td>
                  <td className="small">{a?.lastLoginAt ? <>{relTime(a.lastLoginAt)}<div className="mono muted">{a.lastLoginIp}</div></> : '-'}</td>
                  <td>{!a ? <span className="pill st-dismissed">none</span> : locked ? <span className="pill sev-CRITICAL">locked</span> : a.failed ? <span className="pill sev-MEDIUM">{a.failed} failed</span> : <span className="pill st-executed">ok</span>}</td>
                  <td className="small nowrap">{s ? `until ${new Date(s.expiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : '-'}</td>
                  <td>{a && r !== 'admin' && <Button size="sm" variant="neutral" onClick={() => setConfirm(r)}>Delete</Button>}</td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head"><h3>Sign-in activity</h3><div className="right"><span className="small muted">Real events from this console (organization: Riskbyte Platform)</span></div></div>
        {authEvents.length === 0 ? <div className="panel-body muted">No sign-in activity yet.</div> : (
          <div className="table-wrap tall">
            <table className="tbl">
              <caption className="sr-only">Sign-in events</caption>
              <thead><tr><th>Time</th><th>Event</th><th>User</th><th>Source IP</th><th>Location</th><th>Detail</th></tr></thead>
              <tbody>{authEvents.map((e) => (
                <tr key={e.id}>
                  <td className="nowrap small">{fmtDateTime(e.ts)}</td>
                  <td><span className={`pill ${e.action === 'login_success' ? 'st-executed' : e.action === 'login_failed' || e.meta?.enforced ? 'sev-CRITICAL' : 'st-triaged'}`}>{e.action}</span></td>
                  <td className="mono">{e.user ?? '-'}</td><td className="mono">{e.ip ?? '-'}</td>
                  <td className="small">{String(e.meta?.geo ?? '-')}</td><td className="small">{e.message}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
      <ConfirmModal open={!!confirm} onClose={() => setConfirm(null)} title={`Delete the ${confirm} account?`} confirmLabel="Delete" onConfirm={() => confirm && deleteAccount(confirm)}
        body="Its sessions end immediately and a new account must be created on next sign-in. Recorded in the audit ledger." />
    </>
  );
}

export function Intel() {
  const intel = useStore((s) => s.intel);
  const refresh = useStore((s) => s.refreshIntel);
  const alerts = useStore((s) => s.data.alerts);
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const all = useMemo(() => [...INDICATORS, ...liveIntel().indicators], [intel.fetchedAt, intel.count]); // eslint-disable-line react-hooks/exhaustive-deps
  const list = all.filter((i) => !q || i.value.includes(q.toLowerCase()) || i.category.toLowerCase().includes(q.toLowerCase())).slice(0, 300);
  return (
    <>
      <section className="kpis">
        <div className="kpi"><span className="label">Indicators loaded</span><span className="v">{all.length}</span><span className="s">{intel.count} live · {INDICATORS.length} local</span></div>
        {intel.sources.map((s) => (
          <div key={s.name} className={`kpi ${s.ok ? '' : 'hot'}`}><span className="label">{s.name}</span><span className={`v ${s.ok ? 'ok' : 'coral'}`}>{s.ok ? s.count : 'down'}</span><span className="s">{s.ok ? 'indicators' : s.error}</span></div>
        ))}
        <div className="kpi"><span className="label">Feed status</span><span className="v sm">{intel.status}</span><span className="s">{intel.fetchedAt ? `fetched ${relTime(intel.fetchedAt)}` : 'not fetched yet'} · hourly refresh</span></div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h3>Indicators</h3>
          <div className="right">
            <input className="input" style={{ width: 240, padding: '7px 12px' }} placeholder="Search IP, domain, category…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search indicators" />
            <Button size="sm" variant="secondary" busy={busy} onClick={async () => { setBusy(true); await refresh(); setBusy(false); }}>Refresh feeds</Button>
          </div>
        </div>
        <div className="table-wrap tall">
          <table className="tbl">
            <caption className="sr-only">Threat intelligence indicators</caption>
            <thead><tr><th>Indicator</th><th>Type</th><th>Category</th><th>Confidence</th><th>Source</th><th>Sightings</th><th>Note</th></tr></thead>
            <tbody>{list.map((i) => (
              <tr key={i.source + i.value}>
                <td className="mono nowrap">{i.value}</td><td>{i.type}</td><td>{i.category}</td><td>{Math.round(i.confidence * 100)}%</td>
                <td className="small nowrap">{i.source ?? '-'}</td>
                <td>{alerts.filter((a) => a.intelHits.some((h) => h.value === i.value)).length}</td>
                <td className="small" style={{ maxWidth: 380 }}>{i.note}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        <div className="panel-body small muted">Live feeds are fetched server-side by <code>/api/intel</code> (abuse.ch Feodo Tracker botnet C2 IPs and the OpenPhish community feed), cached at the edge for an hour and in this browser for offline use. Any event IP or domain (or subdomain) matching them raises confidence on the alert. Showing {list.length} of {all.length}.</div>
      </section>
    </>
  );
}

export function LicenseCard() {
  const [check, setCheck] = useState<LicenseCheck | null>(null);
  useEffect(() => { verifyLicense().then(setCheck); }, []);
  return (
    <section className="panel">
      <div className="panel-head"><h3>License</h3><div className="right">
        <span className={`pill ${check?.valid ? 'st-executed' : check ? 'sev-CRITICAL' : 'st-triaged'}`}>{!check ? 'verifying…' : check.valid ? 'Valid' : check.expired ? 'Expired' : 'Invalid signature'}</span>
      </div></div>
      <div className="panel-body stack">
        {[
          ['Licensee', LICENSE.licensee], ['Tier', LICENSE.tier], ['Host quota', `${LICENSE.hostQuota} hosts`], ['Organization quota', `${LICENSE.orgQuota}`],
          ['Expires', `${new Date(LICENSE.expiresAt).toLocaleDateString()} (${check?.daysRemaining ?? '…'} days)`],
          ['Signature', check ? (check.signature === 'valid' ? 'ECDSA P-256 / SHA-256 · verified ✓' : check.signature === 'unavailable' ? 'not verifiable (insecure context)' : 'INVALID') : 'verifying…'],
        ].map(([k, v]) => (
          <div key={k} className="row between" style={{ borderBottom: '1px solid var(--line)', paddingBottom: 8 }}><span className="muted">{k}</span><b style={{ textAlign: 'right' }}>{v}</b></div>
        ))}
        <p className="small muted">The license JSON is verified in your browser against an embedded public key with WebCrypto. The signing key was discarded after issuing, so any edit to the license breaks verification.</p>
      </div>
    </section>
  );
}
