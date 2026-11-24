import { useEffect, useMemo, useState } from 'react';
import { useStore } from '../store/store';
import type { ClientId, Severity } from '../engine/types';
import { CLIENTS } from '../data/clients';
import { ruleById } from '../data/rules';
import { ACTION_PLAIN } from '../data/copy';
import { Button, ClientBadge, EmptyState, HashChip, SeverityBadge, StatusBadge, TriageView, relTime, fmtDateTime, useTick } from '../components/ui';
import { useDecisionGate } from '../components/gates';

const SEVS: (Severity | 'ALL')[] = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function Alerts() {
  useTick(5000);
  const alerts = useStore((s) => s.data.alerts);
  const selectedId = useStore((s) => s.selectedAlertId);
  const set = useStore((s) => s.set);
  const [sev, setSev] = useState<Severity | 'ALL'>('ALL');
  const [client, setClient] = useState<ClientId | 'all'>('all');

  const list = useMemo(
    () => [...alerts].reverse().filter((a) => (sev === 'ALL' || a.severity === sev) && (client === 'all' || a.client === client)),
    [alerts, sev, client],
  );
  const selected = alerts.find((a) => a.id === selectedId) ?? list[0];

  useEffect(() => {
    if (!selectedId && list[0]) set({ selectedAlertId: list[0].id });
  }, [selectedId, list, set]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="label">Analyst view</div>
          <h1 style={{ marginTop: 10 }}>Alerts</h1>
          <p>Every alert is one detection rule firing. Pick one on the left to see the evidence, the AI's verdict, and the response waiting for your approval.</p>
        </div>
        <div className="row">
          <span className="pill chip">{alerts.filter((a) => a.status === 'triaged' || a.status === 'new').length} awaiting decision</span>
          <span className="pill chip">{alerts.length} total</span>
        </div>
      </div>

      <div className="alerts-layout">
        <section className="card pad-sm stack" aria-labelledby="explorer-h">
          <h3 id="explorer-h">Alerts Explorer</h3>
          <div className="filter-chips" role="group" aria-label="Filter by severity">
            {SEVS.map((s) => (
              <button key={s} type="button" className="fchip" aria-pressed={sev === s} onClick={() => setSev(s)}>{s === 'ALL' ? 'All' : s[0] + s.slice(1).toLowerCase()}</button>
            ))}
          </div>
          <label className="field">
            <span className="sr-only">Client</span>
            <select className="select" value={client} onChange={(e) => setClient(e.target.value as ClientId | 'all')} aria-label="Filter by client">
              <option value="all">All clients</option>
              {CLIENTS.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
          <div className="alert-list" role="listbox" aria-label="Alerts, newest first">
            {list.length === 0 && (
              <EmptyState icon="🛡️" title={alerts.length ? 'No alerts match' : 'No alerts yet'}>
                {alerts.length ? 'Try another filter.' : 'No alerts yet. Turn the Engine on and run an attack in the Demo tab.'}
              </EmptyState>
            )}
            {list.map((a) => (
              <button
                key={a.id}
                type="button"
                role="option"
                aria-selected={selected?.id === a.id}
                className={`card clickable alert-item ${selected?.id === a.id ? 'selected' : ''}`}
                onClick={() => set({ selectedAlertId: a.id })}
              >
                <div className="row between"><SeverityBadge sev={a.severity} /><StatusBadge status={a.status} /></div>
                <span className="t">{a.title}</span>
                <div className="row small"><ClientBadge client={a.client} /><span className="mono">{a.proposed.target}</span></div>
                <span className="small muted">{a.id} · {relTime(a.ts)}</span>
              </button>
            ))}
          </div>
        </section>
        {selected ? <Inspector id={selected.id} /> : (
          <section className="card"><EmptyState icon="🔎" title="Inspector">Select an alert to see its evidence and AI triage.</EmptyState></section>
        )}
      </div>
    </div>
  );
}

function Inspector({ id }: { id: string }) {
  const alert = useStore((s) => s.data.alerts.find((a) => a.id === id))!;
  const events = useStore((s) => s.data.events);
  const set = useStore((s) => s.set);
  const decide = useStore((s) => s.decide);
  const gate = useDecisionGate();
  const [busy, setBusy] = useState<null | 'approve' | 'dismiss'>(null);
  const rule = ruleById(alert.ruleId)!;
  const evs = events.filter((e) => alert.eventIds.includes(e.id));

  const go = async (k: 'approve' | 'dismiss') => {
    if (busy) return;
    setBusy(k);
    await decide(alert.id, k);
    setBusy(null);
  };

  return (
    <section className="inspector fade-in" key={id} aria-label={`Inspector for ${alert.id}`}>
      <div className="card">
        <div className="row" style={{ marginBottom: 14 }}>
          <span className="pill chip mono">{alert.ruleId}</span>
          <ClientBadge client={alert.client} />
          <SeverityBadge sev={alert.severity} />
          <StatusBadge status={alert.status} />
        </div>
        <h2>{alert.title}</h2>
        <p className="muted" style={{ marginTop: 10 }}>{rule.plain} <span className="mono small">({rule.mitre})</span></p>
        <div className="row small muted" style={{ marginTop: 14 }}>
          <span>{alert.id}</span>·<span>{fmtDateTime(alert.ts)}</span>·
          <button type="button" className="link-btn" onClick={() => set({ selectedCaseId: alert.caseId, tab: 'cases' })}>Case {alert.caseId} →</button>
        </div>
        <div className="meta-grid" style={{ marginTop: 18 }}>
          <div><div className="label">Host</div><div className="v">{alert.host ?? '-'}</div></div>
          <div><div className="label">User</div><div className="v">{alert.user ?? '-'}</div></div>
          <div><div className="label">Source IP</div><div className="v">{alert.ip ?? '-'}</div></div>
        </div>
      </div>

      <div className="card">
        <div className="card-title"><h3>🤖 AI Triage</h3></div>
        {alert.triage ? <TriageView t={alert.triage} /> : (
          <div className="row muted"><span className="spinner" aria-hidden /> AI is thinking… reading the evidence.</div>
        )}
      </div>

      <div className="card">
        <div className="card-title"><h3>Threat intel hits</h3><span className="pill chip">{alert.intelHits.length} match{alert.intelHits.length === 1 ? '' : 'es'}</span></div>
        {alert.intelHits.length === 0 ? <p className="muted">No indicator matched. The alert rests on behaviour alone.</p> : (
          <div className="table-wrap">
            <table className="tbl">
              <caption className="sr-only">Threat intelligence matches</caption>
              <thead><tr><th>Indicator</th><th>Category</th><th>Confidence</th></tr></thead>
              <tbody>{alert.intelHits.map((h) => (
                <tr key={h.value}><td className="mono">{h.value}</td><td>{h.category}</td><td>{Math.round(h.confidence * 100)}%</td></tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-title"><h3>Containment Response</h3></div>
        <div className="stack">
          <div>Proposed: <span className="proposal">{alert.proposed.action} {alert.proposed.target}</span></div>
          <p className="small muted">This would {ACTION_PLAIN[alert.proposed.action]}. Dry-run: nothing is actually changed on any machine.</p>
          {alert.outcome ? (
            <div className="outcome">
              <StatusBadge status={alert.status} />
              <span>{alert.outcome.kind === 'approved' ? 'Approved and executed (dry-run)' : 'Dismissed'} by <b>{alert.outcome.by}</b> at {fmtDateTime(alert.outcome.at)}</span>
              <HashChip hash={alert.outcome.hash} label={`block #${alert.outcome.blockIndex}`} />
            </div>
          ) : (
            <div className="row">
              <Button onClick={() => go('approve')} disabledReason={gate ?? (!alert.triage ? 'Wait for AI triage to finish' : null)} busy={busy === 'approve'}>Approve &amp; Execute</Button>
              <Button variant="neutral" onClick={() => go('dismiss')} disabledReason={gate} busy={busy === 'dismiss'}>Dismiss Alert</Button>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-title"><h3>Correlated Telemetry</h3><span className="pill chip">{evs.length} event{evs.length === 1 ? '' : 's'}</span></div>
        <div className="table-wrap">
          <table className="tbl">
            <caption className="sr-only">Events linked to this alert</caption>
            <thead><tr><th>Timestamp</th><th>Host</th><th>Process</th><th>Action</th><th>Command line / message</th></tr></thead>
            <tbody>
              {evs.length === 0 && <tr><td colSpan={5} className="muted">Events were trimmed from storage (only the newest 2000 are kept).</td></tr>}
              {evs.map((e) => (
                <tr key={e.id}>
                  <td className="mono nowrap">{fmtDateTime(e.ts)}</td>
                  <td className="mono nowrap">{e.host ?? '-'}</td>
                  <td className="mono nowrap">{e.process ?? '-'}</td>
                  <td className="mono nowrap">{e.action}</td>
                  <td className="cmd">{e.message}{e.ip ? `  [ip ${e.ip}]` : ''}{e.domain ? `  [domain ${e.domain}]` : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
