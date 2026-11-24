import { useEffect, useState } from 'react';
import { useStore } from '../store/store';
import type { ClientId } from '../engine/types';
import { ATTACKS, attackById, defaultTarget, type AttackDef, type AttackType } from '../engine/generators';
import { clientName } from '../data/clients';
import { Button, Modal, SeverityBadge, Switch, relTime, useTick } from '../components/ui';

export default function DemoWorkspace() {
  useTick(1000);
  const [picked, setPicked] = useState<AttackType | null>(null);
  const continuous = useStore((s) => s.continuous);
  const setContinuous = useStore((s) => s.setContinuous);
  const launches = useStore((s) => s.launches);
  const enter = useStore((s) => s.enter);
  const running = launches.some((l) => l.status === 'running');
  const remaining = continuous.nextAt ? Math.max(0, Math.ceil((continuous.nextAt - Date.now()) / 1000)) : null;

  return (
    <>
      <section className="panel">
        <div className="panel-body row">
          <span className="pill chip">Simulation · inert events · documentation IP ranges</span>
          <span className="grow" />
          <Switch checked={continuous.on} onChange={setContinuous} label="Continuous attacks" />
          {continuous.on && remaining !== null && <span className="countdown">next in {remaining}s</span>}
        </div>
      </section>

      <section className="attack-grid" aria-label="Attacks">
        {ATTACKS.map((a) => <AttackCard key={a.id} a={a} disabled={running} onPick={() => setPicked(a.id)} />)}
      </section>

      <section className="panel">
        <div className="panel-head"><h3>Launch history</h3><div className="right">
          <Button size="sm" variant="secondary" onClick={() => enter('analyst', 'overview')}>Open analyst console</Button>
          <Button size="sm" variant="secondary" onClick={() => enter('ingest', 'stream')}>Open telemetry stream</Button>
        </div></div>
        {launches.length === 0 ? <div className="panel-body muted">No attacks launched yet.</div> : (
          <div className="table-wrap">
            <table className="tbl">
              <caption className="sr-only">Launched attacks</caption>
              <thead><tr><th>When</th><th>Attack</th><th>Organization</th><th>Target</th><th>Events</th><th>Status</th></tr></thead>
              <tbody>{launches.map((l) => (
                <tr key={l.id}>
                  <td className="nowrap">{relTime(new Date(l.startedAt).toISOString())}</td>
                  <td><b>{attackById(l.attack).label}</b></td>
                  <td>{l.attack === 'ledger_tamper' ? 'Platform' : clientName(l.org)}</td>
                  <td className="mono">{l.target}</td>
                  <td>{l.sent} / {l.total}</td>
                  <td><span className={`pill ${l.status === 'delivered' ? 'st-executed' : l.status === 'running' ? 'st-new' : l.status === 'failed' ? 'sev-CRITICAL' : 'st-dismissed'}`}>{l.status}</span>{l.detail && <div className="small muted">{l.detail}</div>}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>

      {picked && <LaunchModal type={picked} onClose={() => setPicked(null)} />}
    </>
  );
}

function AttackCard({ a, disabled, onPick }: { a: AttackDef; disabled: boolean; onPick: () => void }) {
  return (
    <article className="card attack">
      <div className="row between"><SeverityBadge sev={a.severity} /><span className="meta">{a.mitre}</span></div>
      <h4>{a.label}</h4>
      <span className="meta">{a.tactic}</span>
      <p>{a.description}</p>
      <div><Button onClick={onPick} disabledReason={disabled ? 'Another attack is in progress' : null}>Launch…</Button></div>
    </article>
  );
}

function LaunchModal({ type, onClose }: { type: AttackType; onClose: () => void }) {
  const a = attackById(type);
  const orgs = useStore((s) => s.data.orgs);
  const launch = useStore((s) => s.launchAttack);
  const cancel = useStore((s) => s.cancelLaunch);
  const enter = useStore((s) => s.enter);
  const [org, setOrg] = useState<ClientId | null>(a.targetKind === 'ledger' ? orgs[0]?.id ?? null : null);
  const [target, setTarget] = useState('');
  const [intensity, setIntensity] = useState(3);
  const [launchId, setLaunchId] = useState<number | null>(null);
  const launchRec = useStore((s) => s.launches.find((l) => l.id === launchId));

  useEffect(() => { if (org) setTarget(defaultTarget(org, type)); }, [org, type]);

  const go = async () => {
    if (!org) return;
    const p = launch(type, org, target, intensity);
    // launchAttack records the launch synchronously before its first await
    setLaunchId(useStore.getState().launches[0]?.id ?? null);
    await p;
  };

  const ledger = a.targetKind === 'ledger';
  return (
    <Modal open onClose={onClose} wide label={`Launch ${a.label}`}
      title={<div><div className="label">{a.tactic} · {a.mitre}</div><h3 style={{ marginTop: 6 }}>{a.label}</h3></div>}>
      {!launchRec ? (
        <div className="stack-lg">
          <p className="muted">{a.description}</p>
          {ledger ? (
            <div className="banner">This attack targets the platform’s audit ledger directly. No telemetry is sent; the change is caught by hash-chain verification.</div>
          ) : (
            <>
              <div className="field">
                <span>Which organization do you want to attack?</span>
                <div className="org-pick" role="radiogroup" aria-label="Organization">
                  {orgs.map((o) => (
                    <button key={o.id} type="button" role="radio" aria-checked={org === o.id} className="org-opt" onClick={() => setOrg(o.id)}>
                      <span className="avatar" aria-hidden>{o.name[0]}</span>
                      <span><b>{o.name}</b><span className="small muted">{o.sector}</span></span>
                    </button>
                  ))}
                </div>
              </div>
              {org && (
                <div className="grid g2">
                  <label className="field"><span>Target {a.targetKind}</span><input className="input mono" value={target} onChange={(e) => setTarget(e.target.value)} spellCheck={false} /></label>
                  <label className="field"><span>Intensity · {intensity} / 5</span><input className="range" type="range" min={1} max={5} value={intensity} onChange={(e) => setIntensity(Number(e.target.value))} /><span className="help">More events, faster.</span></label>
                </div>
              )}
            </>
          )}
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button variant="secondary" onClick={onClose}>Cancel</Button>
            <Button onClick={go} disabledReason={!org ? 'Choose an organization' : null}>Launch attack</Button>
          </div>
        </div>
      ) : (
        <div className="stack-lg">
          <div className="row">
            <span className={`pill ${launchRec.status === 'delivered' ? 'st-executed' : launchRec.status === 'running' ? 'st-new' : 'sev-CRITICAL'}`}>{launchRec.status}</span>
            <b>{ledger ? 'Audit ledger' : `${clientName(launchRec.org)} · ${launchRec.target}`}</b>
          </div>
          <div>
            <div className="small muted" style={{ marginBottom: 6 }}>{launchRec.sent} of {launchRec.total} {ledger ? 'operation' : 'events'} delivered{launchRec.detail ? ` · ${launchRec.detail}` : ''}</div>
            <div className="progress-line"><span style={{ width: `${launchRec.total ? (launchRec.sent / launchRec.total) * 100 : 0}%` }} /></div>
          </div>
          {launchRec.status === 'running' ? (
            <div className="row" style={{ justifyContent: 'flex-end' }}><Button variant="secondary" onClick={cancel}>Stop attack</Button></div>
          ) : (
            <div className="row" style={{ justifyContent: 'flex-end' }}>
              <Button variant="secondary" onClick={onClose}>Close</Button>
              {ledger
                ? <Button onClick={() => enter('admin', 'ledger')}>Open administrator console</Button>
                : <>
                    <Button variant="secondary" onClick={() => enter('ingest', 'stream')}>Telemetry console</Button>
                    <Button onClick={() => enter('analyst', 'overview')}>Security analyst console</Button>
                  </>}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
