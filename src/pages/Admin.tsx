import { useState } from 'react';
import { useStore, effectiveKey } from '../store/store';
import { RULES } from '../data/rules';
import { INDICATORS } from '../data/indicators';
import { ACTION_LABEL } from '../data/copy';
import type { Rule } from '../engine/types';
import { Button, ConfirmModal, Modal, SeverityBadge } from '../components/ui';
import { useAdminGate } from '../components/gates';

export default function Admin() {
  const data = useStore((s) => s.data);
  const audit = useStore((s) => s.audit);
  const settings = useStore((s) => s.settings);
  const [rule, setRule] = useState<Rule | null>(null);
  const provider = effectiveKey(settings) ? 'GEMINI' : 'HEURISTIC';
  const avg = data.counters.batches ? (data.counters.totalMs / data.counters.batches).toFixed(1) : '0.0';
  const openCases = data.cases.filter((c) => c.status === 'open').length;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="label">Platform</div>
          <h1 style={{ marginTop: 10 }}>Admin Overview 🛡️</h1>
          <p>The health of the whole SOC on one page: how much telemetry came in, what is still open, which AI is deciding, and whether the audit ledger is still trustworthy.</p>
        </div>
      </div>

      <section className="grid g5" aria-label="Platform metrics">
        <div className="card metric"><div className="label">Total Telemetry Ingested</div><div className="num">{data.counters.totalIngested}</div><span className="small muted">events since last reset</span></div>
        <div className="card metric"><div className="label">Active Incidents</div><div className="num coral">{openCases}</div><span className="small muted">open cases</span></div>
        <div className="card metric"><div className="label">Triage AI Provider</div><div className="num sm">{provider}</div><span className="small muted">{provider === 'GEMINI' ? settings.model : 'local, deterministic'}</span></div>
        <div className="card metric"><div className="label">Audit Forensic Ledger</div>
          <div className={`num sm ${audit.intact ? 'ok' : 'coral'}`}>{audit.intact ? 'Intact ✓' : 'TAMPERED'}</div>
          <span className="small muted">{audit.intact ? `${data.audit.length} blocks verified` : `broken at block #${audit.brokenAt}`}</span>
        </div>
        <div className="card metric"><div className="label">Avg processing time</div><div className="num sm">{avg}<span style={{ fontSize: '.5em' }}> ms</span></div><span className="small muted">per batch, measured live</span></div>
      </section>

      <AdminTools />

      <section className="band ink on-dark" aria-labelledby="rules-h">
        <div className="band-head">
          <div>
            <div className="label">Detection</div>
            <h2 id="rules-h" style={{ marginTop: 8 }}>Active Sigma Detection Rules</h2>
            <p className="muted">Ten shareable, Sigma-style signatures. Click a rule to read its YAML.</p>
          </div>
          <span className="pill chip">{RULES.length} active</span>
        </div>
        <div className="table-wrap" style={{ color: 'var(--ink)' }}>
          <table className="tbl">
            <caption className="sr-only">Detection rules</caption>
            <thead><tr><th>ID</th><th>Title</th><th>MITRE</th><th>Severity</th><th>Mapped action</th></tr></thead>
            <tbody>
              {RULES.map((r) => (
                <tr key={r.id} className="clickable" tabIndex={0} onClick={() => setRule(r)} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setRule(r))}>
                  <td className="mono nowrap">{r.id}</td>
                  <td><b>{r.title}</b><div className="small muted">{r.plain}</div></td>
                  <td className="mono">{r.mitre}</td>
                  <td><SeverityBadge sev={r.severity} /></td>
                  <td className="mono nowrap">{r.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card" aria-labelledby="intel-h">
        <div className="card-title">
          <div><div className="label">Threat Intel</div><h3 id="intel-h" style={{ marginTop: 6 }}>Known-bad indicators</h3></div>
          <span className="pill chip">{INDICATORS.length} indicators</span>
        </div>
        <div className="table-wrap">
          <table className="tbl">
            <caption className="sr-only">Threat intelligence indicators</caption>
            <thead><tr><th>Indicator</th><th>Type</th><th>Category</th><th>Confidence</th><th>Note</th></tr></thead>
            <tbody>{INDICATORS.map((i) => (
              <tr key={i.value}><td className="mono nowrap">{i.value}</td><td>{i.type}</td><td>{i.category}</td><td>{Math.round(i.confidence * 100)}%</td><td className="small">{i.note}</td></tr>
            ))}</tbody>
          </table>
        </div>
        <p className="small muted" style={{ marginTop: 12 }}>All IPs are from documentation ranges (RFC 5737: 198.51.100.0/24, 203.0.113.0/24) except 1.2.3.4, a widely used placeholder that is treated as a stand-in here.</p>
      </section>

      <Modal open={!!rule} onClose={() => setRule(null)} kind="drawer" label={`Rule ${rule?.id}`}
        title={rule && <div><div className="label mono">{rule.id} · {rule.mitre}</div><h3 style={{ marginTop: 6 }}>{rule.title}</h3></div>}>
        {rule && (
          <div className="stack-lg">
            <div className="row"><SeverityBadge sev={rule.severity} /><span className="pill chip">Action: {ACTION_LABEL[rule.action]}</span></div>
            <p>{rule.plain}</p>
            <pre className="yaml" aria-label="Sigma-style YAML">{rule.yaml}</pre>
            <p className="small muted">Sigma is a shared, vendor-neutral format for detection rules, so the same signature can be loaded into many SIEMs.</p>
          </div>
        )}
      </Modal>
    </div>
  );
}

function AdminTools() {
  const gate = useAdminGate();
  const audit = useStore((s) => s.audit);
  const verify = useStore((s) => s.verifyAudit);
  const tamper = useStore((s) => s.tamper);
  const repair = useStore((s) => s.repair);
  const reset = useStore((s) => s.resetDemo);
  const toast = useStore((s) => s.toast);
  const blocks = useStore((s) => s.data.audit.length);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const wrap = (k: string, fn: () => Promise<unknown>) => async () => { setBusy(k); await fn(); setBusy(null); };

  return (
    <section className={`band ${audit.intact ? 'coral' : 'ink on-dark'}`} aria-labelledby="tools-h">
      <div className="band-head">
        <div>
          <div className="label">Admin tools · forensic ledger</div>
          <h2 id="tools-h" style={{ marginTop: 8 }}>{audit.intact ? 'Can anyone secretly edit the log? Try it.' : `Tampering detected at block #${audit.brokenAt}`}</h2>
          <p className="muted">
            {audit.intact
              ? 'Simulate tampering edits one stored record without fixing its hash. Every block depends on the one before it, so verification instantly breaks and every badge turns red.'
              : 'The stored record no longer matches its SHA-256 hash. Repair rebuilds the hashes from the broken block onward and appends a ledger.repaired block, so the repair itself is on the record.'}
          </p>
        </div>
        <span className={`chain-badge ${audit.intact ? 'ok' : 'bad'}`}>{audit.intact ? `Hash Chain: Intact ✓ (${blocks} blocks)` : `Hash Chain: TAMPERED (#${audit.brokenAt})`}</span>
      </div>
      <div className="row">
        <Button variant="dark" onClick={wrap('v', async () => { const s = await verify(); toast(s.intact ? `Verified: all ${s.blocks} blocks intact` : `Tampering detected at block #${s.brokenAt}`, s.intact ? 'ok' : 'error'); })} busy={busy === 'v'}>Verify audit now</Button>
        <Button variant={audit.intact ? 'secondary' : 'secondary'} onClick={wrap('t', tamper)} disabledReason={gate ?? (blocks < 2 ? 'Run an attack first so there is something to tamper with' : !audit.intact ? 'Already tampered; repair first' : null)} busy={busy === 't'}>Simulate tampering</Button>
        <Button variant={audit.intact ? 'secondary' : 'primary'} onClick={wrap('r', repair)} disabledReason={gate ?? (audit.intact ? 'Nothing to repair; the chain is intact' : null)} busy={busy === 'r'}>Repair (rebuild chain)</Button>
        <Button variant="neutral" onClick={() => setConfirm(true)} disabledReason={gate}>Reset Demo Data</Button>
      </div>
      {gate && <p className="small" style={{ marginTop: 14 }}>🔒 {gate}</p>}
      <ConfirmModal open={confirm} onClose={() => setConfirm(false)} title="Reset demo data?" confirmLabel="Yes, reset" onConfirm={reset}
        body="All events, alerts, cases and audit blocks are removed. A new ledger starts with a genesis block plus a system.reset block signed by you." />
    </section>
  );
}
