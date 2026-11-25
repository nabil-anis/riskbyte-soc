import { useMemo, useState } from 'react';
import type { AgentStep, Alert } from '../engine/types';
import { useStore } from '../store/store';
import { ruleById } from '../data/rules';
import { ACTION_PLAIN } from '../data/copy';
import { Button, ClientBadge, HashChip, SeverityBadge, StatusBadge, TriageView, fmtDateTime, fmtTime } from './ui';

export const STEP_LABEL: Record<AgentStep['kind'], string> = {
  detect: 'Detected', correlate: 'Correlated', enrich: 'Enriched', case: 'Incident', triage: 'AI triage',
  propose: 'Recommendation', await: 'Needs approval', execute: 'Executed', dismiss: 'Dismissed', auto: 'Auto-executed',
};
const STEP_ICON: Record<AgentStep['kind'], string> = {
  detect: '!', correlate: '⋯', enrich: 'i', case: '▣', triage: 'AI', propose: '→', await: '?', execute: '✓', dismiss: '×', auto: '✓',
};

export function KindDot({ kind }: { kind: AgentStep['kind'] }) {
  return <span className={`kdot k-${kind}`} aria-hidden>{STEP_ICON[kind]}</span>;
}

export function AgentTimeline({ alert }: { alert: Alert }) {
  const pending = !alert.triage;
  return (
    <ol className="timeline" aria-label="Agent timeline">
      {alert.timeline.map((s, i) => (
        <li key={i} className={s.kind === 'await' && !alert.outcome ? 'waiting' : ''}>
          <KindDot kind={s.kind} />
          <div className="tt">{STEP_LABEL[s.kind]}<span>{fmtTime(s.ts)}</span></div>
          <div className="tx">{s.text}</div>
        </li>
      ))}
      {pending && (
        <li className="waiting">
          <span className="kdot k-triage" aria-hidden><span className="spinner" style={{ width: 12, height: 12 }} /></span>
          <div className="tt">AI triage</div>
          <div className="tx">Agent is reading the evidence…</div>
        </li>
      )}
    </ol>
  );
}

/** What the agent is asking the human to do, and the approve/dismiss controls. */
export function DecisionBox({ alert, canDecide }: { alert: Alert; canDecide: boolean }) {
  const decide = useStore((s) => s.decide);
  const [busy, setBusy] = useState<null | 'approve' | 'dismiss'>(null);
  const go = async (k: 'approve' | 'dismiss') => {
    if (busy) return;
    setBusy(k);
    await decide(alert.id, k);
    setBusy(null);
  };
  if (alert.outcome) {
    return (
      <div className="decision done">
        <div className="label">{alert.outcome.auto ? 'Agent acted under policy' : 'Decision recorded'}</div>
        <div className="row">
          <StatusBadge status={alert.status} />
          <span>
            {alert.outcome.kind === 'approved' ? <>Containment <code>{alert.proposed.action} {alert.proposed.target}</code> is enforced</> : 'Dismissed, no action taken'}
            {' '}by <b>{alert.outcome.by}</b> · {fmtDateTime(alert.outcome.at)}
          </span>
        </div>
        <div><HashChip hash={alert.outcome.hash} label={`audit #${alert.outcome.blockIndex}`} /></div>
      </div>
    );
  }
  return (
    <div className="decision">
      <div className="label">{alert.triage ? 'Agent recommendation · awaiting your approval' : 'Agent is still triaging'}</div>
      <div>
        <span className="proposal">{alert.proposed.action} {alert.proposed.target}</span>
      </div>
      <SelfTargetWarning target={alert.proposed.target} />
      <p className="small muted">This will {ACTION_PLAIN[alert.proposed.action]}. Riskbyte enforces it on all later telemetry and console sign-ins; it can be released from Administrator → Containment.</p>
      <div className="row">
        <Button onClick={() => go('approve')} busy={busy === 'approve'} disabledReason={!canDecide ? 'Only analysts and administrators can approve' : !alert.triage ? 'Wait for AI triage to finish' : null}>Approve &amp; execute</Button>
        <Button variant="neutral" onClick={() => go('dismiss')} busy={busy === 'dismiss'} disabledReason={!canDecide ? 'Only analysts and administrators can dismiss' : null}>Dismiss</Button>
      </div>
    </div>
  );
}

function SelfTargetWarning({ target }: { target: string }) {
  const ip = useStore((s) => s.client?.ip);
  const users = useStore((s) => Object.values(s.accounts).map((a) => a?.username));
  const t = target.toLowerCase();
  if (t === ip) return <div className="banner bad small">This is <b>your own address</b>. Approving blocks this browser from the analyst and ingestion consoles (Administrator can still sign in and release it).</div>;
  if (users.includes(t)) return <div className="banner bad small">This is a <b>real console account</b>. Approving takes effect on its next sign-in and ends its current session.</div>;
  return null;
}

export function AlertDetail({ alert, canDecide }: { alert: Alert; canDecide: boolean }) {
  const events = useStore((s) => s.data.events);
  const go = useStore((s) => s.go);
  const rule = ruleById(alert.ruleId)!;
  const evs = events.filter((e) => alert.eventIds.includes(e.id));
  return (
    <div className="detail fade-in" key={alert.id}>
      <div className="panel">
        <div className="panel-body stack">
          <div className="row"><span className="pill chip mono">{alert.id}</span><SeverityBadge sev={alert.severity} /><StatusBadge status={alert.status} /><ClientBadge client={alert.client} /></div>
          <h2 style={{ fontSize: 30 }}>{alert.title}</h2>
          <p className="muted">{rule.plain} <span className="mono small">{rule.id} · {rule.mitre}</span></p>
          <div className="meta-grid">
            <div><div className="label">Host</div><div className="v">{alert.host ?? '-'}</div></div>
            <div><div className="label">User</div><div className="v">{alert.user ?? '-'}</div></div>
            <div><div className="label">Source IP</div><div className="v">{alert.ip ?? '-'}</div></div>
          </div>
          <div className="row small muted">
            Detected {fmtDateTime(alert.ts)} · <button type="button" className="lnk" onClick={() => go('incidents', { selectedCaseId: alert.caseId })}>Incident {alert.caseId}</button>
          </div>
        </div>
      </div>

      <DecisionBox alert={alert} canDecide={canDecide} />

      <div className="cols-2e">
        <div className="panel">
          <div className="panel-head"><h3>What the agent did</h3></div>
          <div className="panel-body"><AgentTimeline alert={alert} /></div>
        </div>
        <div className="panel">
          <div className="panel-head"><h3>AI assessment</h3></div>
          <div className="panel-body">
            {alert.triage ? <TriageView t={alert.triage} compact /> : <div className="row muted"><span className="spinner" aria-hidden /> Agent is reading the evidence…</div>}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head"><h3>Threat intelligence</h3><div className="right"><span className="pill chip">{alert.intelHits.length} match{alert.intelHits.length === 1 ? '' : 'es'}</span></div></div>
        {alert.intelHits.length === 0 ? <div className="panel-body muted">No known-bad indicator matched; the alert rests on behaviour.</div> : (
          <div className="table-wrap">
            <table className="tbl">
              <caption className="sr-only">Threat intelligence matches</caption>
              <thead><tr><th>Indicator</th><th>Type</th><th>Category</th><th>Confidence</th></tr></thead>
              <tbody>{alert.intelHits.map((h) => <tr key={h.value}><td className="mono">{h.value}</td><td>{h.type}</td><td>{h.category}</td><td>{Math.round(h.confidence * 100)}%</td></tr>)}</tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head"><h3>Evidence</h3><div className="right"><span className="pill chip">{evs.length} event{evs.length === 1 ? '' : 's'}</span></div></div>
        <div className="table-wrap">
          <table className="tbl">
            <caption className="sr-only">Correlated telemetry</caption>
            <thead><tr><th>Time</th><th>Source</th><th>Host</th><th>User</th><th>Process</th><th>Action</th><th>Message / command line</th></tr></thead>
            <tbody>
              {evs.length === 0 && <tr><td colSpan={7} className="muted">Events were rotated out of storage (newest 2000 are kept).</td></tr>}
              {evs.map((e) => (
                <tr key={e.id}>
                  <td className="mono nowrap">{fmtTime(e.ts)}</td><td>{e.source}</td><td className="mono">{e.host ?? '-'}</td><td className="mono">{e.user ?? '-'}</td>
                  <td className="mono">{e.process ?? '-'}</td><td className="mono nowrap">{e.action}</td>
                  <td className="cmd">{e.message}{e.ip ? `  [ip ${e.ip}]` : ''}{e.domain ? `  [${e.domain}]` : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export interface FeedItem { ts: string; alertId: string; kind: AgentStep['kind']; text: string; client: string }

export function useAgentFeed(limit = 200): FeedItem[] {
  const alerts = useStore((s) => s.data.alerts);
  return useMemo(() => {
    const items: FeedItem[] = [];
    for (const a of alerts) for (const s of a.timeline) items.push({ ts: s.ts, alertId: a.id, kind: s.kind, text: s.text, client: a.client });
    items.sort((x, y) => y.ts.localeCompare(x.ts));
    return items.slice(0, limit);
  }, [alerts, limit]);
}

export function ActivityFeed({ items, onOpen }: { items: FeedItem[]; onOpen: (alertId: string) => void }) {
  if (!items.length) return <div className="panel-body muted">No agent activity yet. It appears here as soon as telemetry triggers a detection.</div>;
  return (
    <ul className="feed">
      {items.map((f, i) => (
        <li key={`${f.alertId}-${i}-${f.ts}`}>
          <span className="ts">{fmtTime(f.ts)}</span>
          <KindDot kind={f.kind} />
          <div><button type="button" className="lnk" onClick={() => onOpen(f.alertId)}>{f.alertId}</button><span className="small muted">{STEP_LABEL[f.kind]} · </span>{f.text}</div>
        </li>
      ))}
    </ul>
  );
}
