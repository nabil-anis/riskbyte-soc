import { useStore } from '../store/store';
import { ClientBadge, EmptyState, Modal, SeverityBadge, StatusBadge, fmtDateTime, relTime } from '../components/ui';

export default function Cases() {
  const cases = useStore((s) => s.data.cases);
  const alerts = useStore((s) => s.data.alerts);
  const selectedId = useStore((s) => s.selectedCaseId);
  const set = useStore((s) => s.set);
  const selected = cases.find((c) => c.id === selectedId);
  const list = [...cases].reverse();

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="label">Incidents</div>
          <h1 style={{ marginTop: 10 }}>Cases</h1>
          <p>One attacker often triggers many alerts on the same laptop. Riskbyte groups them into a single case.</p>
        </div>
        <div className="row">
          <span className="pill chip">{cases.filter((c) => c.status === 'open').length} open</span>
          <span className="pill chip">{cases.length} total</span>
        </div>
      </div>
      <div className="card pad-sm">
        {list.length === 0 ? (
          <EmptyState icon="🗂️" title="No cases yet">Cases appear as soon as the first alert fires. Run an attack in the Demo tab.</EmptyState>
        ) : (
          <div className="table-wrap tall">
            <table className="tbl">
              <caption>All cases, newest first · click a row to open it</caption>
              <thead><tr><th>Case ID</th><th>Client</th><th>Target Entity</th><th>Severity</th><th>Status</th><th>Opened</th><th>Alerts</th></tr></thead>
              <tbody>
                {list.map((c) => (
                  <tr key={c.id} className="clickable" tabIndex={0} onClick={() => set({ selectedCaseId: c.id })}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), set({ selectedCaseId: c.id }))}>
                    <td className="mono nowrap">{c.id}</td>
                    <td><ClientBadge client={c.client} /></td>
                    <td className="mono">{c.entity} <span className="muted small">({c.entityType})</span></td>
                    <td><SeverityBadge sev={c.severity} /></td>
                    <td><StatusBadge status={c.status} /></td>
                    <td className="nowrap">{relTime(c.openedAt)}</td>
                    <td><b>{c.alertIds.length}</b></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Modal open={!!selected} onClose={() => set({ selectedCaseId: null })} kind="drawer" label={`Case ${selected?.id}`}
        title={selected && <div><div className="label">Case {selected.id}</div><h3 style={{ marginTop: 6 }}>{selected.entity}</h3></div>}>
        {selected && (
          <div className="stack-lg">
            <div className="row"><ClientBadge client={selected.client} /><SeverityBadge sev={selected.severity} /><StatusBadge status={selected.status} /></div>
            <p className="muted small">Opened {fmtDateTime(selected.openedAt)} · groups every alert on this {selected.entityType}. Severity is the highest of its alerts. It closes when every alert is approved or dismissed.</p>
            <div className="stack">
              {selected.alertIds.map((id) => {
                const a = alerts.find((x) => x.id === id);
                if (!a) return null;
                return (
                  <button key={id} type="button" className="card clickable alert-item" onClick={() => set({ selectedAlertId: id, selectedCaseId: null, tab: 'alerts' })}>
                    <div className="row between"><SeverityBadge sev={a.severity} /><StatusBadge status={a.status} /></div>
                    <span className="t">{a.title}</span>
                    <span className="small muted">{a.id} · {a.ruleId} · {fmtDateTime(a.ts)} · open in Alerts →</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
