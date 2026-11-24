import { useEffect, useState } from 'react';
import { useStore } from '../store/store';
import { Button, ClientBadge, copy, fmtDateTime } from '../components/ui';

export default function Audit() {
  const blocks = useStore((s) => s.data.audit);
  const audit = useStore((s) => s.audit);
  const verify = useStore((s) => s.verifyAudit);
  const set = useStore((s) => s.set);
  const toast = useStore((s) => s.toast);
  const [open, setOpen] = useState<Record<number, boolean>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => { verify(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const list = [...blocks].reverse();
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="label">Forensics</div>
          <h1 style={{ marginTop: 10 }}>Audit Trail</h1>
          <p>Every action is a block. Each block's SHA-256 hash covers the previous block's hash, so editing any old row breaks every link after it. Tamper-evident, not tamper-proof.</p>
        </div>
        <div className="row">
          <span className={`chain-badge ${audit.intact ? 'ok' : 'bad'}`} role="status">
            {audit.intact ? 'Hash Chain: Intact (SHA-256) ✓' : `Hash Chain: TAMPERED at block #${audit.brokenAt}`}
          </span>
          <Button variant="secondary" busy={busy} onClick={async () => { setBusy(true); const s = await verify(); setBusy(false); toast(s.intact ? `Verified: ${s.blocks} blocks intact` : `Tampering detected at block #${s.brokenAt}`, s.intact ? 'ok' : 'error'); }}>Verify now</Button>
        </div>
      </div>
      <p className="small muted">Last verified {fmtDateTime(audit.checkedAt)} · verification runs on page open and after every new block. Formula: <code>hash = SHA256(prevHash + ts + actor + kind + detail)</code></p>
      <div className="card pad-sm">
        <div className="table-wrap tall">
          <table className="tbl">
            <caption>{blocks.length} blocks, newest first</caption>
            <thead><tr><th>#</th><th>Timestamp</th><th>Client</th><th>Actor / Role</th><th>Audit Event</th><th>Target Alert</th><th>Operation Detail</th><th>Hash</th></tr></thead>
            <tbody>
              {list.map((b) => {
                const broken = !audit.intact && b.index === audit.brokenAt;
                return (
                  <tr key={b.index} className={broken ? 'broken' : ''}>
                    <td className="mono">{b.index}{broken && <div><span className="pill sev-CRITICAL" style={{ marginTop: 4 }}>broken</span></div>}</td>
                    <td className="nowrap small">{fmtDateTime(b.ts)}</td>
                    <td><ClientBadge client={b.client} /></td>
                    <td className="mono small">{b.actor}</td>
                    <td className="mono small nowrap">{b.kind}</td>
                    <td className="mono small">{b.alertId ? <button type="button" className="link-btn" onClick={() => set({ selectedAlertId: b.alertId!, tab: 'alerts' })}>{b.alertId}</button> : '-'}</td>
                    <td className="small" style={{ minWidth: 220 }}>{b.detail}</td>
                    <td>
                      <div className="hash-cell">
                        <div className="row" style={{ gap: 6 }}>
                          <code>{b.hash.slice(0, 10)}</code>
                          <button type="button" className="link-btn" onClick={() => copy(b.hash).then(() => toast('Hash copied'))}>copy</button>
                          <button type="button" className="link-btn" aria-expanded={!!open[b.index]} onClick={() => setOpen((o) => ({ ...o, [b.index]: !o[b.index] }))}>{open[b.index] ? 'hide' : 'show full'}</button>
                        </div>
                        {open[b.index] && (
                          <div className="full">
                            <div><b>hash</b> {b.hash}</div>
                            <div><b>prev</b> {b.prevHash}</div>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
