import { useStore } from '../store/store';
import { CHECKLIST } from '../data/copy';
import { TOKENS } from '../engine/auth';
import { Modal, Button } from './ui';

export function DemoGuideDrawer() {
  const open = useStore((s) => s.guideOpen);
  const checklist = useStore((s) => s.checklist);
  const toggle = useStore((s) => s.toggleCheck);
  const set = useStore((s) => s.set);
  const done = CHECKLIST.filter((_, i) => checklist[i]).length;
  return (
    <Modal open={open} onClose={() => set({ guideOpen: false })} kind="drawer" label="Demo guide"
      title={<div><div className="label">Demo guide</div><h3 style={{ marginTop: 6 }}>Presentation checklist 🎯</h3></div>}>
      <div className="stack-lg">
        <div className="row between">
          <span className="muted small">{done} of {CHECKLIST.length} done · ticks are saved in this browser</span>
          <Button variant="secondary" size="sm" onClick={() => CHECKLIST.forEach((_, i) => checklist[i] && toggle(i))}>Untick all</Button>
        </div>
        <div className="bar"><span style={{ width: `${(done / CHECKLIST.length) * 100}%` }} /></div>
        <ul className="checklist">
          {CHECKLIST.map((item, i) => (
            <li key={i}>
              <label>
                <input type="checkbox" checked={!!checklist[i]} onChange={() => toggle(i)} />
                <span className={checklist[i] ? 'done' : ''}>{i + 1}. {item}</span>
              </label>
            </li>
          ))}
        </ul>
        <div className="card pad-sm" style={{ background: 'var(--bg)' }}>
          <div className="label" style={{ marginBottom: 8 }}>Simulated role tokens</div>
          <div className="stack small">
            {Object.entries(TOKENS).map(([r, t]) => (
              <div key={r} className="row between"><span>{r}</span><code>Bearer {t}</code></div>
            ))}
          </div>
        </div>
        <div className="card pad-sm" style={{ background: 'var(--bg)' }}>
          <div className="label" style={{ marginBottom: 8 }}>Real vs simulated, in one line</div>
          <p className="small">Detection, AI triage, the approval gate and the SHA-256 audit chain are real code running live in your browser; only the attacker, the network sockets and the containment execution (dry-run) are simulated.</p>
        </div>
      </div>
    </Modal>
  );
}
