import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useStore, type DemoRun } from '../store/store';
import { CLIENTS, clientById } from '../data/clients';
import { scenariosFor, scenarioById, type Scenario } from '../data/scenarios';
import { ruleById } from '../data/rules';
import { STEP_TITLES, WHY_IT_MATTERS, whatThisMeans, ACTION_PLAIN, DISCLAIMER } from '../data/copy';
import { SPEED_MS } from '../store/persist';
import { ATTACK_TYPES, defaultTarget, type AttackType } from '../engine/generators';
import type { ClientId } from '../engine/types';
import { Button, ConfirmModal, SeverityBadge, Switch, TriageView, ClientBadge, useTick, fmtTime } from '../components/ui';
import { useDecisionGate, useEngineGate, useAdminGate, ENGINE_OFF } from '../components/gates';

const num = (id: string) => Number(id.split('-')[1]);
const reduceMotion = () => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

export default function Demo() {
  const engineOn = useStore((s) => s.engineOn);
  const client = useStore((s) => s.demoClient);
  const set = useStore((s) => s.set);
  const run = useStore((s) => s.demoRun);
  const profile = clientById(client);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (run?.runId && panelRef.current) panelRef.current.scrollIntoView({ behavior: reduceMotion() ? 'auto' : 'smooth', block: 'start' });
  }, [run?.runId]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="label">Attack Lab</div>
          <h1 style={{ marginTop: 10 }}>See an attack, start to finish 🎯</h1>
          <p>Pick an organisation, launch a simulated attack, and watch Riskbyte detect it, ask the AI for a verdict, and wait for you to approve the response.</p>
        </div>
      </div>

      {!engineOn && (
        <div className="banner" role="status">
          <span aria-hidden style={{ fontSize: 22 }}>⏻</span>
          <div className="grow"><b>Engine is off.</b> Turn it on from the top bar to run attacks.</div>
          <Button onClick={() => useStore.getState().setEngine(true)}>Turn Engine on</Button>
        </div>
      )}

      {/* Band 1: selector + profile */}
      <section className="band cream" aria-labelledby="client-h">
        <div className="band-head">
          <div>
            <div className="label">Step A · Choose the organisation</div>
            <h2 id="client-h" style={{ marginTop: 8 }}>{profile.name}</h2>
            <p className="muted">{profile.sector}</p>
          </div>
          <label className="field" style={{ minWidth: 300 }}>
            <span>Client</span>
            <select className="select" value={client} onChange={(e) => set({ demoClient: e.target.value as ClientId })}>
              {CLIENTS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
            </select>
          </label>
        </div>
        <div className="profile-cols fade-in" key={client}>
          <div>
            <div className="label">What they do</div>
            <p style={{ marginTop: 8 }}>{profile.what}</p>
          </div>
          <div>
            <div className="label">Digital platforms &amp; assets</div>
            <ul>{profile.platforms.map((p) => <li key={p}>{p}</li>)}</ul>
          </div>
          <div>
            <div className="label">Main threat surface &amp; risks</div>
            <ul>{profile.risks.map((p) => <li key={p}>{p}</li>)}</ul>
          </div>
        </div>
        <p className="small muted" style={{ marginTop: 20 }}>{DISCLAIMER}</p>
      </section>

      {/* Band 2: scenarios */}
      <section className="band coral" aria-labelledby="scen-h">
        <div className="band-head">
          <div>
            <div className="label">Step B · Launch an attack</div>
            <h2 id="scen-h" style={{ marginTop: 8 }}>Four realistic attacks on {profile.short}</h2>
            <p className="muted">Each one sends simulated log events through the real detection pipeline. Nothing touches a real system.</p>
          </div>
        </div>
        <div className="grid g2">
          {scenariosFor(client).map((s) => <ScenarioCard key={s.id} s={s} />)}
        </div>
      </section>

      {/* Band 3: live execution */}
      <section className="band ink on-dark" aria-labelledby="exec-h" ref={panelRef} style={{ scrollMarginTop: 150 }}>
        <div className="band-head">
          <div>
            <div className="label">Step C · Watch Riskbyte respond</div>
            <h2 id="exec-h" style={{ marginTop: 8 }}>Live execution</h2>
            <p className="muted">Seven steps, from the attacker's first move to a tamper-evident record of your decision.</p>
          </div>
          {run && <span className="pill chip">{run.status === 'running' ? 'Running…' : run.status === 'error' ? 'Error' : 'Pipeline complete'}</span>}
        </div>
        {run ? <ExecutionPanel run={run} key={run.runId} /> : (
          <div className="empty" style={{ color: 'var(--card)' }}>
            <div className="big" aria-hidden>🛡️</div>
            <h3>Nothing running yet</h3>
            <p style={{ color: 'var(--muted-dark)' }}>Turn the Engine on, then press <b>Run Attack</b> on any card above. The steps appear here one by one.</p>
          </div>
        )}
      </section>

      <Playground />
      <ResetCard />
    </div>
  );
}

function ScenarioCard({ s }: { s: Scenario }) {
  const run = useStore((st) => st.demoRun);
  const pg = useStore((st) => st.playground.running);
  const runScenario = useStore((st) => st.runScenario);
  const engineGate = useEngineGate();
  const busy = run?.status === 'running';
  const mine = busy && run?.scenarioId === s.id;
  const reason = engineGate ?? (pg ? 'The playground is running; wait for it to finish' : busy && !mine ? 'Another attack is running' : null);
  const rule = ruleById(s.ruleId)!;
  return (
    <article className={`card scenario-card ${mine ? 'running' : ''}`}>
      <div className="row between">
        <SeverityBadge sev={s.severity} />
        <span className="pill chip mono" title={rule.title}>{s.ruleId} · {rule.mitre}</span>
      </div>
      <h3>{s.title}</h3>
      <p className="sum">{s.summary}</p>
      <div className="row between">
        <span className="small muted">Detected by: {rule.title}</span>
        <Button onClick={() => runScenario(s.id)} disabledReason={mine ? null : reason} busy={mine}>{mine ? 'Running…' : 'Run Attack'}</Button>
      </div>
    </article>
  );
}

function Explain({ step, scenario, n, override }: { step: number; scenario: Scenario; n: number; override?: string }) {
  const c = clientById(scenario.client);
  return (
    <div className="explain">
      <div><b>What this means: </b><span>{override ?? whatThisMeans(step, { attackShort: scenario.attackShort, n })}</span></div>
      <div><b>Why this matters for {c.name}: </b><span>{WHY_IT_MATTERS[scenario.client][step]}</span></div>
    </div>
  );
}

function Kv({ k, v, hl }: { k: string; v: ReactNode; hl?: boolean }) {
  return <div><span className="k">{k.padEnd(12, ' ')}</span><span className={hl ? 'hl' : ''}>{v}</span></div>;
}

function ExecutionPanel({ run }: { run: DemoRun }) {
  const s = scenarioById(run.scenarioId)!;
  const data = useStore((st) => st.data);
  const speed = useStore((st) => SPEED_MS[st.settings.speed]);
  const auditStatus = useStore((st) => st.audit);
  const decide = useStore((st) => st.decide);
  const gate = useDecisionGate();
  const [shown, setShown] = useState(0);
  const [deciding, setDeciding] = useState<null | 'approve' | 'dismiss'>(null);
  const stepRefs = useRef<(HTMLDivElement | null)[]>([]);

  const events = useMemo(
    () => data.events.filter((e) => num(e.id) > run.eventCountBefore && num(e.id) <= run.eventCountBefore + s.events.length),
    [data.events, run.eventCountBefore, s.events.length],
  );
  const alert = useMemo(() => {
    if (run.alertId) return data.alerts.find((a) => a.id === run.alertId);
    return data.alerts.find((a) => a.scenarioId === s.id && a.ruleId === s.ruleId && num(a.id) > run.alertCountBefore);
  }, [data.alerts, run.alertId, run.alertCountBefore, s.id, s.ruleId]);
  const block = alert?.outcome ? data.audit.find((b) => b.index === alert.outcome!.blockIndex) : undefined;

  const available = (step: number) => {
    switch (step) {
      case 1: return true;
      case 2: return events.length > 0;
      case 3: case 4: return !!alert;
      case 5: case 6: return !!alert?.triage;
      case 7: return !!alert?.outcome;
      default: return false;
    }
  };

  // Reveal steps one at a time at the configured speed, waiting for the data each step needs.
  useEffect(() => {
    if (shown >= 7 || !available(shown + 1)) return;
    const t = setTimeout(() => setShown((n) => n + 1), shown === 0 ? 150 : speed);
    return () => clearTimeout(t);
  });

  useEffect(() => {
    if (shown > 1) stepRefs.current[shown - 1]?.scrollIntoView({ behavior: reduceMotion() ? 'auto' : 'smooth', block: 'nearest' });
  }, [shown]);

  const doDecide = async (k: 'approve' | 'dismiss') => {
    if (!alert || deciding) return;
    setDeciding(k);
    await decide(alert.id, k);
    setDeciding(null);
  };

  if (run.status === 'error') {
    return <div className="banner bad" style={{ color: 'var(--ink)' }}><b>Run failed:</b> {run.error}</div>;
  }

  const rule = ruleById(s.ruleId)!;
  const c = clientById(s.client);
  const waitingText = (step: number) =>
    step === 5 ? 'AI is thinking… reading the evidence' : step === 7 ? 'Waiting for your decision at step 6' : step === 2 ? 'Receiving events…' : 'Working…';

  const steps: ReactNode[] = [
    // 1
    <>
      <div className="data">
        <Kv k="adversary" v="simulated attacker (classroom exercise)" />
        <Kv k="target" v={`${c.name} · ${s.events[0].host ?? '-'}`} />
        <Kv k="technique" v={`${rule.mitre} · ${rule.title}`} hl />
        <div style={{ marginTop: 8, whiteSpace: 'normal' }}>{s.attackNarrative}</div>
      </div>
      <Explain step={0} scenario={s} n={s.events.length} />
    </>,
    // 2
    <>
      <div className="data">
        <Kv k="request" v={`POST /api/ingest → 200 accepted=${events.length}`} hl />
        <Kv k="hosts" v={[...new Set(events.map((e) => e.host).filter(Boolean))].join(', ') || '-'} />
        <Kv k="process" v={[...new Set(events.map((e) => e.process).filter(Boolean))].join(', ') || '-'} />
        <Kv k="time" v={events[0] ? `${fmtTime(events[0].ts)} – ${fmtTime(events[events.length - 1].ts)}` : '-'} />
        <Kv k="processing" v={run.processingMs !== undefined ? `${run.processingMs} ms (measured)` : 'measuring…'} />
        {events[0] && (
          <div style={{ marginTop: 8, color: 'var(--muted-dark)', whiteSpace: 'pre-wrap' }}>
            {JSON.stringify({ id: events[0].id, ts: events[0].ts, client: events[0].client, source: events[0].source, host: events[0].host, user: events[0].user, ip: events[0].ip, action: events[0].action, message: events[0].message }, null, 1)}
          </div>
        )}
      </div>
      <Explain step={1} scenario={s} n={events.length} />
    </>,
    // 3
    <>
      <div className="data">
        <Kv k="rule" v={`${rule.id} · ${rule.title}`} hl />
        <Kv k="severity" v={rule.severity} />
        <Kv k="mitre" v={rule.mitre} />
        <Kv k="client" v={c.name} />
        <Kv k="alert" v={`${alert?.id ?? '-'} → case ${alert?.caseId ?? '-'}`} />
        {run.dedupedFrom && <div style={{ marginTop: 8, color: 'var(--amber)', whiteSpace: 'normal' }}>Deduplicated: this rule already fired for the same target in the last 60 seconds, so Riskbyte linked the new events to {run.dedupedFrom} instead of opening a duplicate alert.</div>}
        <div style={{ marginTop: 8, whiteSpace: 'normal' }}>In plain words: {rule.plain}</div>
      </div>
      <Explain step={2} scenario={s} n={events.length} />
    </>,
    // 4
    <>
      <div className="data">
        {alert && alert.intelHits.length ? alert.intelHits.map((h) => (
          <div key={h.value}><span className="hl">✓ {h.value}</span> <span className="k">({h.type})</span> {h.category} · confidence {Math.round(h.confidence * 100)}%</div>
        )) : <div>no match: none of the addresses or domains are on the known-bad list</div>}
      </div>
      <Explain step={3} scenario={s} n={events.length} override={alert && !alert.intelHits.length ? 'Nothing matched the known-bad list, so the verdict relies on behaviour alone.' : undefined} />
    </>,
    // 5
    <>
      <div className="data" style={{ fontFamily: 'var(--sans)', fontSize: 14.5 }}>{alert?.triage && <TriageView t={alert.triage} compact />}</div>
      <Explain step={4} scenario={s} n={events.length} />
    </>,
    // 6
    <>
      <div className="data">
        <Kv k="proposed" v={`${alert?.proposed.action} ${alert?.proposed.target}`} hl />
        <Kv k="effect" v={alert ? ACTION_PLAIN[alert.proposed.action] : ''} />
        <Kv k="mode" v="dry-run: nothing is actually changed on any machine" />
      </div>
      <div className="gate">
        {alert?.outcome ? (
          <span className={`pill ${alert.outcome.kind === 'approved' ? 'st-executed' : 'st-dismissed'}`}>
            {alert.outcome.kind === 'approved' ? '✓ Approved & executed (dry-run)' : 'Dismissed'} by {alert.outcome.by}
          </span>
        ) : (
          <>
            <Button onClick={() => doDecide('approve')} disabledReason={gate} busy={deciding === 'approve'}>Approve &amp; Execute Action</Button>
            <Button variant="secondary" onClick={() => doDecide('dismiss')} disabledReason={gate} busy={deciding === 'dismiss'}>Dismiss</Button>
            <span className="small" style={{ color: 'var(--muted-dark)' }}>⏸ Riskbyte is waiting for a human decision.</span>
          </>
        )}
      </div>
      <Explain step={5} scenario={s} n={events.length} />
    </>,
    // 7
    <>
      {block && (
        <div className="data">
          <Kv k="block" v={`#${block.index} · ${block.kind}`} hl />
          <Kv k="sha-256" v={<span style={{ wordBreak: 'break-all' }}>{block.hash}</span>} />
          <Kv k="prev hash" v={<span style={{ wordBreak: 'break-all' }}>{block.prevHash}</span>} />
          <Kv k="actor" v={block.actor} />
          <Kv k="client" v={c.name} />
          <Kv k="time" v={new Date(block.ts).toLocaleString()} />
          <Kv k="chain" v={auditStatus.intact ? `intact ✓ (${auditStatus.blocks} blocks verified)` : `TAMPERED at block #${auditStatus.brokenAt}`} hl />
        </div>
      )}
      <Explain step={6} scenario={s} n={events.length}
        override={alert?.outcome?.kind === 'dismissed' ? 'You dismissed the alert. That decision was still written to the tamper-evident log, so nobody can quietly change it later.' : undefined} />
    </>,
  ];

  return (
    <div className="stack-lg">
      <div className="presenter"><b>Presenter line:</b> {s.presenterLine}</div>
      <div className="row"><ClientBadge client={s.client} /><SeverityBadge sev={s.severity} /><span className="pill chip">{s.title}</span></div>
      <div className="exec-steps">
        {STEP_TITLES.map((title, i) => {
          const n = i + 1;
          const done = n <= shown;
          const active = n === shown + 1 && (run.status === 'running' || n === 7 || available(n));
          if (!done && !active) return null;
          return (
            <div key={n} ref={(el) => (stepRefs.current[i] = el)} className={`step ${done ? 'done' : active ? 'active' : ''} ${n === 7 && !done ? 'pending' : ''}`} aria-live="polite">
              <div className="n" aria-hidden>{done ? '✓' : n}</div>
              <div style={{ minWidth: 0 }}>
                <div className="row between">
                  <h4>{n}. {title}{n === 7 && done && alert?.outcome?.kind === 'dismissed' ? ' (dismissal)' : ''}</h4>
                  {!done && <span className="row small" style={{ color: 'var(--muted-dark)' }}>{n !== 7 && <span className="spinner" aria-hidden />} {waitingText(n)}</span>}
                </div>
                {done && steps[i]}
              </div>
            </div>
          );
        })}
      </div>
      {shown >= 6 && (
        <div className="happened fade-in">
          <div className="label">In plain English</div>
          <h3 style={{ marginTop: 6 }}>What Happened?</h3>
          <p>{s.happened}</p>
          {alert?.outcome && (
            <p style={{ marginTop: 10 }}>
              <b>Your decision:</b> {alert.outcome.kind === 'approved' ? `approved ${alert.proposed.action} ${alert.proposed.target} (dry-run)` : 'dismissed the alert'}, recorded as audit block #{alert.outcome.blockIndex}.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function Playground() {
  const engineOn = useStore((s) => s.engineOn);
  const pg = useStore((s) => s.playground);
  const auto = useStore((s) => s.autoAttack);
  const demoRunning = useStore((s) => s.demoRun?.status === 'running');
  const launch = useStore((s) => s.launchPlayground);
  const cancel = useStore((s) => s.cancelPlayground);
  const setAuto = useStore((s) => s.setAutoAttack);
  const demoClient = useStore((s) => s.demoClient);
  const [type, setType] = useState<AttackType>('brute');
  const [client, setClient] = useState<ClientId>(demoClient);
  const [target, setTarget] = useState(defaultTarget(demoClient, 'brute'));
  const [edited, setEdited] = useState(false);
  const [intensity, setIntensity] = useState(3);
  useTick(1000);

  useEffect(() => { setClient(demoClient); }, [demoClient]);
  useEffect(() => { if (!edited) setTarget(defaultTarget(client, type)); }, [client, type, edited]);

  const meta = ATTACK_TYPES.find((a) => a.id === type)!;
  const reason = !engineOn ? ENGINE_OFF : demoRunning ? 'A demo attack is running' : null;
  const remaining = auto.nextAt ? Math.max(0, Math.ceil((auto.nextAt - Date.now()) / 1000)) : null;

  return (
    <section className="card" aria-labelledby="pg-h">
      <div className="card-title">
        <div>
          <div className="label">Attack Playground</div>
          <h2 id="pg-h" style={{ marginTop: 8 }}>Mix your own attack 🧪</h2>
          <p className="muted" style={{ marginTop: 8 }}>Choose the attack, the target and how hard it hits. Events stream in live; watch the terminal and the Alerts tab.</p>
        </div>
        <div className="stack" style={{ alignItems: 'flex-end' }}>
          <Switch checked={auto.on} onChange={setAuto} label="Auto-attack" disabledReason={!engineOn ? ENGINE_OFF : undefined} />
          {auto.on && remaining !== null && <span className="countdown" aria-live="off">next random attack in {remaining}s</span>}
          <span className="small muted">A random scenario every 20-30s. Never auto-approves.</span>
        </div>
      </div>
      <div className="playground-grid">
        <label className="field">
          <span>Attack type</span>
          <select className="select" value={type} onChange={(e) => { setType(e.target.value as AttackType); setEdited(false); }}>
            {ATTACK_TYPES.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Client</span>
          <select className="select" value={client} onChange={(e) => { setClient(e.target.value as ClientId); setEdited(false); }}>
            {CLIENTS.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Target {meta.targetKind}</span>
          <input className="input mono" value={target} onChange={(e) => { setTarget(e.target.value); setEdited(true); }} spellCheck={false} />
        </label>
        <label className="field">
          <span>Intensity: {intensity} / 5</span>
          <input className="range" type="range" min={1} max={5} value={intensity} onChange={(e) => setIntensity(Number(e.target.value))} aria-valuetext={`Intensity ${intensity} of 5`} />
          <span className="help">Higher = more events, faster.</span>
        </label>
      </div>
      <div className="row" style={{ marginTop: 20 }}>
        {pg.running
          ? <Button variant="dark" onClick={cancel}>Stop</Button>
          : <Button onClick={() => launch(type, client, target, intensity, meta.label)} disabledReason={reason}>Launch</Button>}
        {(pg.running || pg.sent > 0) && (
          <div className="grow stack" style={{ gap: 6, minWidth: 200 }}>
            <span className="small">{pg.label}: {pg.sent} / {pg.total} events sent{pg.running ? '…' : ''}</span>
            <div className="progress-line"><span style={{ width: `${pg.total ? (pg.sent / pg.total) * 100 : 0}%` }} /></div>
          </div>
        )}
      </div>
    </section>
  );
}

function ResetCard() {
  const gate = useAdminGate();
  const reset = useStore((s) => s.resetDemo);
  const [open, setOpen] = useState(false);
  return (
    <section className="banner coral">
      <span aria-hidden style={{ fontSize: 20 }}>↺</span>
      <div className="grow"><b>Start fresh before presenting?</b> Reset Demo Data clears events, alerts, cases and the audit ledger, then starts a new ledger with a genesis block.</div>
      <Button variant="secondary" onClick={() => setOpen(true)} disabledReason={gate}>Reset Demo Data</Button>
      <ConfirmModal open={open} onClose={() => setOpen(false)} title="Reset demo data?" confirmLabel="Yes, reset" onConfirm={reset}
        body="All events, alerts, cases and audit blocks are removed. A new ledger starts with a genesis block plus a system.reset block signed by you." />
    </section>
  );
}
