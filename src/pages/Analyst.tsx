import { useEffect, useMemo, useState } from 'react';
import { useStore } from '../store/store';
import type { Alert, ClientId, Severity } from '../engine/types';
import { SEV_RANK } from '../engine/types';
import { Button, ClientBadge, EmptyState, Modal, SeverityBadge, StatusBadge, VerdictPill, fmtDateTime, relTime, useTick } from '../components/ui';
import { ActivityFeed, AlertDetail, useAgentFeed } from '../components/agent';
import { LiveLog, useMonitorStats } from '../components/Live';
import { clientName } from '../data/clients';

const awaiting = (a: Alert) => a.status === 'new' || a.status === 'triaged';

export default function AnalystWorkspace() {
  const view = useStore((s) => s.view);
  if (view === 'alerts') return <AlertQueue />;
  if (view === 'incidents') return <Incidents />;
  if (view === 'activity') return <Activity />;
  return <Overview />;
}

export function Bars({ rows }: { rows: { label: string; n: number; color?: string }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.n));
  return (
    <div className="bars">
      {rows.map((r) => (
        <div className="bar-row" key={r.label}>
          <span>{r.label}</span>
          <div className="track" aria-hidden><div className="fill" style={{ width: `${(r.n / max) * 100}%`, background: r.color }} /></div>
          <span className="n">{r.n}</span>
        </div>
      ))}
    </div>
  );
}

const SEV_COLOR: Record<Severity, string> = { CRITICAL: '#B5532F', HIGH: '#D97757', MEDIUM: '#E8B65B', LOW: '#D9D6CA' };

function Overview() {
  useTick(5000);
  const alerts = useStore((s) => s.data.alerts);
  const cases = useStore((s) => s.data.cases);
  const orgs = useStore((s) => s.data.orgs);
  const go = useStore((s) => s.go);
  const feed = useAgentFeed(14);
  const queue = [...alerts].filter(awaiting).sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.ts.localeCompare(a.ts));
  const triaged = alerts.filter((a) => a.triage);
  const avgTriage = triaged.length ? Math.round(triaged.reduce((s, a) => s + (a.triage?.ms ?? 0), 0) / triaged.length) : 0;
  const auto = alerts.filter((a) => a.outcome?.auto).length;
  const open = (id: string) => go('alerts', { selectedAlertId: id });

  return (
    <>
      <section className="kpis" aria-label="Key metrics">
        <div className={`kpi ${queue.length ? 'hot' : ''}`}><span className="label">Awaiting your approval</span><span className={`v ${queue.length ? 'coral' : ''}`}>{queue.length}</span><span className="s">agent recommendations pending</span></div>
        <div className="kpi"><span className="label">Open incidents</span><span className="v">{cases.filter((c) => c.status === 'open').length}</span><span className="s">{cases.length} total</span></div>
        <div className="kpi"><span className="label">Critical open</span><span className="v">{queue.filter((a) => a.severity === 'CRITICAL').length}</span><span className="s">highest severity</span></div>
        <div className="kpi"><span className="label">Alerts</span><span className="v">{alerts.length}</span><span className="s">{alerts.filter((a) => a.status === 'executed').length} contained · {alerts.filter((a) => a.status === 'dismissed').length} dismissed</span></div>
        <div className="kpi"><span className="label">Handled by agent</span><span className="v">{auto}</span><span className="s">auto-executed under policy</span></div>
        <div className="kpi"><span className="label">Avg AI triage</span><span className="v">{avgTriage}<span style={{ fontSize: '.5em' }}> ms</span></span><span className="s">measured per alert</span></div>
      </section>

      <div className="cols-2">
        <section className="panel" aria-labelledby="q-h">
          <div className="panel-head"><h3 id="q-h">Approval queue</h3><div className="right"><Button variant="secondary" size="sm" onClick={() => go('alerts')}>Open alert queue</Button></div></div>
          {queue.length === 0 ? <AllClear /> : queue.slice(0, 8).map((a) => <QueueRow key={a.id} a={a} onOpen={() => open(a.id)} />)}
        </section>
        <section className="panel" aria-labelledby="act-h">
          <div className="panel-head"><h3 id="act-h">Agent activity</h3><div className="right"><Button variant="secondary" size="sm" onClick={() => go('activity')}>View all</Button></div></div>
          <ActivityFeed items={feed} onOpen={open} />
        </section>
      </div>

      <div className="cols-2e">
        <section className="panel">
          <div className="panel-head"><h3>Open alerts by severity</h3></div>
          <div className="panel-body"><Bars rows={(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((s) => ({ label: s[0] + s.slice(1).toLowerCase(), n: queue.filter((a) => a.severity === s).length, color: SEV_COLOR[s] }))} /></div>
        </section>
        <section className="panel">
          <div className="panel-head"><h3>Alerts by organization</h3></div>
          <div className="panel-body"><Bars rows={orgs.map((o) => ({ label: o.name, n: alerts.filter((a) => a.client === o.id).length }))} /></div>
        </section>
      </div>
    </>
  );
}

function AllClear() {
  const { perMin, lastScan } = useMonitorStats();
  return (
    <div className="allclear">
      <h4><span className="pulse-dot" aria-hidden />All clear · standing by</h4>
      <p className="muted small">The agent is scanning live telemetry ({perMin} events in the last minute{lastScan !== null ? `, last scan ${lastScan}s ago` : ''}). You will be called in here only when it recommends an action that needs a human.</p>
      <LiveLog lines={12} height={200} title="Detection pipeline" />
    </div>
  );
}

function QueueRow({ a, onOpen }: { a: Alert; onOpen: () => void }) {
  const decide = useStore((s) => s.decide);
  const [busy, setBusy] = useState(false);
  return (
    <div className="queue-item">
      <SeverityBadge sev={a.severity} />
      <div style={{ minWidth: 0 }}>
        <button type="button" className="t" onClick={onOpen}>{a.title}</button>
        <div className="small muted" style={{ marginTop: 4 }}>
          {a.id} · {clientName(a.client)} · {relTime(a.ts)} · recommends <code>{a.proposed.action} {a.proposed.target}</code>
          {a.triage && <> · <VerdictPill v={a.triage.verdict} /> {a.triage.confidence}%</>}
        </div>
      </div>
      <div className="act">
        <Button size="sm" busy={busy} disabledReason={!a.triage ? 'Agent is still triaging' : null} onClick={async () => { setBusy(true); await decide(a.id, 'approve'); setBusy(false); }}>Approve</Button>
        <Button size="sm" variant="secondary" onClick={onOpen}>Review</Button>
      </div>
    </div>
  );
}

type StatusFilter = 'pending' | 'all' | 'resolved';

function AlertQueue() {
  useTick(10000);
  const alerts = useStore((s) => s.data.alerts);
  const orgs = useStore((s) => s.data.orgs);
  const selectedId = useStore((s) => s.selectedAlertId);
  const set = useStore((s) => s.set);
  const [status, setStatus] = useState<StatusFilter>(() => (alerts.some(awaiting) ? 'pending' : 'all'));
  const [sev, setSev] = useState<Severity | 'ALL'>('ALL');
  const [org, setOrg] = useState<ClientId | 'all'>('all');

  const list = useMemo(() => [...alerts].reverse().filter((a) =>
    (status === 'all' || (status === 'pending' ? awaiting(a) : !awaiting(a))) &&
    (sev === 'ALL' || a.severity === sev) && (org === 'all' || a.client === org)), [alerts, status, sev, org]);
  const selected = alerts.find((a) => a.id === selectedId) ?? list[0];

  useEffect(() => {
    if (selected && selected.id !== selectedId) set({ selectedAlertId: selected.id });
  }, [selected, selectedId, set]);

  return (
    <div className="split">
      <section className="panel" aria-label="Alerts">
        <div className="panel-head" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 10 }}>
          <div className="seg" role="tablist" aria-label="Status filter">
            {(['pending', 'all', 'resolved'] as StatusFilter[]).map((s) => (
              <button key={s} role="tab" type="button" aria-selected={status === s} onClick={() => setStatus(s)}>
                {s === 'pending' ? `Needs approval (${alerts.filter(awaiting).length})` : s === 'all' ? 'All' : 'Resolved'}
              </button>
            ))}
          </div>
          <div className="row" style={{ gap: 8 }}>
            <select className="select" style={{ flex: 1, padding: '8px 36px 8px 12px' }} value={sev} onChange={(e) => setSev(e.target.value as Severity | 'ALL')} aria-label="Severity">
              <option value="ALL">All severities</option>
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <select className="select" style={{ flex: 1, padding: '8px 36px 8px 12px' }} value={org} onChange={(e) => setOrg(e.target.value)} aria-label="Organization">
              <option value="all">All organizations</option>
              {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          </div>
        </div>
        <div className="list" role="listbox" aria-label="Alerts, newest first">
          {list.length === 0 && <EmptyState icon="✓" title={alerts.length ? 'Nothing here' : 'No alerts yet'}>{alerts.length ? 'Try another filter.' : 'Alerts appear when telemetry matches a detection rule.'}</EmptyState>}
          {list.map((a) => (
            <button key={a.id} type="button" role="option" aria-selected={selected?.id === a.id} className="list-item" onClick={() => set({ selectedAlertId: a.id })}>
              <div className="row between"><SeverityBadge sev={a.severity} /><StatusBadge status={a.status} /></div>
              <span className="t">{a.title}</span>
              <span className="small muted">{a.id} · {clientName(a.client)} · <span className="mono">{a.proposed.target}</span> · {relTime(a.ts)}</span>
            </button>
          ))}
        </div>
      </section>
      {selected ? <AlertDetail alert={selected} canDecide /> : (
        <section className="panel"><EmptyState icon="⚑" title="Select an alert">The agent’s investigation and recommendation appear here.</EmptyState></section>
      )}
    </div>
  );
}

function Incidents() {
  const cases = useStore((s) => s.data.cases);
  const alerts = useStore((s) => s.data.alerts);
  const selectedId = useStore((s) => s.selectedCaseId);
  const set = useStore((s) => s.set);
  const go = useStore((s) => s.go);
  const selected = cases.find((c) => c.id === selectedId);
  const list = [...cases].reverse();
  return (
    <>
      <section className="panel">
        {list.length === 0 ? <EmptyState icon="▣" title="No incidents">Incidents open automatically when the first alert fires on a host or user.</EmptyState> : (
          <div className="table-wrap tall">
            <table className="tbl">
              <caption className="sr-only">Incidents</caption>
              <thead><tr><th>Incident</th><th>Organization</th><th>Entity</th><th>Severity</th><th>Status</th><th>Alerts</th><th>Pending</th><th>Opened</th></tr></thead>
              <tbody>
                {list.map((c) => {
                  const pend = c.alertIds.filter((id) => { const a = alerts.find((x) => x.id === id); return a && awaiting(a); }).length;
                  return (
                    <tr key={c.id} className="clickable" tabIndex={0} onClick={() => set({ selectedCaseId: c.id })} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), set({ selectedCaseId: c.id }))}>
                      <td className="mono nowrap">{c.id}</td><td><ClientBadge client={c.client} /></td>
                      <td className="mono">{c.entity} <span className="muted small">({c.entityType})</span></td>
                      <td><SeverityBadge sev={c.severity} /></td><td><StatusBadge status={c.status} /></td>
                      <td><b>{c.alertIds.length}</b></td><td>{pend ? <span className="pill sev-MEDIUM">{pend}</span> : <span className="muted">0</span>}</td>
                      <td className="nowrap">{relTime(c.openedAt)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <Modal open={!!selected} onClose={() => set({ selectedCaseId: null })} kind="drawer" label={`Incident ${selected?.id}`}
        title={selected && <div><div className="label">Incident {selected.id}</div><h3 style={{ marginTop: 6 }}>{selected.entity}</h3></div>}>
        {selected && (
          <div className="stack-lg">
            <div className="row"><ClientBadge client={selected.client} /><SeverityBadge sev={selected.severity} /><StatusBadge status={selected.status} /></div>
            <p className="muted small">Opened {fmtDateTime(selected.openedAt)}. Groups every alert on this {selected.entityType}; severity is the highest of its alerts; closes when every alert is resolved.</p>
            <div className="stack">
              {selected.alertIds.map((id) => {
                const a = alerts.find((x) => x.id === id);
                if (!a) return null;
                return (
                  <button key={id} type="button" className="card clickable alert-item" onClick={() => go('alerts', { selectedAlertId: id, selectedCaseId: null })}>
                    <div className="row between"><SeverityBadge sev={a.severity} /><StatusBadge status={a.status} /></div>
                    <span className="t">{a.title}</span>
                    <span className="small muted">{a.id} · {a.ruleId} · {fmtDateTime(a.ts)} · open →</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}

function Activity() {
  const orgs = useStore((s) => s.data.orgs);
  const go = useStore((s) => s.go);
  const all = useAgentFeed(500);
  const [org, setOrg] = useState<ClientId | 'all'>('all');
  const items = all.filter((f) => org === 'all' || f.client === org);
  return (
    <section className="panel">
      <div className="panel-head">
        <h3>Agent log</h3>
        <div className="right">
          <select className="select" style={{ width: 240, padding: '8px 36px 8px 12px' }} value={org} onChange={(e) => setOrg(e.target.value)} aria-label="Organization">
            <option value="all">All organizations</option>
            {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
          <span className="pill chip">{items.length} steps</span>
        </div>
      </div>
      <ActivityFeed items={items} onOpen={(id) => go('alerts', { selectedAlertId: id })} />
    </section>
  );
}
