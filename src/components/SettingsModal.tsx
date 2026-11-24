import { useEffect, useState } from 'react';
import { useStore } from '../store/store';
import { ENV_KEY, SPEED_MS, type Settings } from '../store/persist';
import { testConnection } from '../engine/gemini';
import { Button, ConfirmModal, Modal, Switch } from './ui';

export function SettingsModal() {
  const open = useStore((s) => s.settingsOpen);
  const settings = useStore((s) => s.settings);
  const update = useStore((s) => s.updateSettings);
  const set = useStore((s) => s.set);
  const toast = useStore((s) => s.toast);
  const clearAllData = useStore((s) => s.clearAllData);
  const [key, setKey] = useState(settings.apiKey);
  const [model, setModel] = useState(settings.model);
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  useEffect(() => {
    if (open) { setKey(settings.apiKey); setModel(settings.model); setResult(null); setShow(false); }
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const close = () => set({ settingsOpen: false });
  const save = () => {
    update({ apiKey: key.trim(), model: model.trim() || 'gemini-2.5-flash' });
    useStore.getState().log('INFO', `settings saved: AI provider ${key.trim() || ENV_KEY ? `gemini (${model.trim() || 'gemini-2.5-flash'})` : 'heuristic (no API key set)'}`);
    toast(key.trim() ? 'Saved. New alerts will be triaged by Gemini.' : 'Saved. Using the local heuristic engine.', 'ok');
    close();
  };
  const test = async () => {
    setTesting(true); setResult(null);
    const r = await testConnection(key.trim() || ENV_KEY, model.trim() || 'gemini-2.5-flash');
    setTesting(false);
    setResult(r.ok ? { ok: true, text: `Connected ✓ ${model} replied in ${r.ms} ms` } : { ok: false, text: `Failed after ${r.ms} ms: ${r.error}` });
  };
  const usingEnv = !key.trim() && !!ENV_KEY;

  return (
    <>
      <Modal open={open} onClose={close} title="Settings" wide>
        <div className="stack-lg">
          <section className="stack">
            <div className="label">AI triage · Google Gemini</div>
            <label className="field">
              <span>Gemini API key</span>
              <div className="row" style={{ flexWrap: 'nowrap' }}>
                <input className="input mono" type={show ? 'text' : 'password'} value={key} onChange={(e) => setKey(e.target.value)} placeholder="Paste your key (starts with AIza…)" autoComplete="off" spellCheck={false} />
                <Button variant="secondary" size="sm" onClick={() => setShow(!show)} ariaLabel={show ? 'Hide key' : 'Show key'}>{show ? 'Hide' : 'Show'}</Button>
              </div>
              <span className="help">
                {usingEnv ? 'Using key from build environment. ' : ''}Stored only in this browser (localStorage). Never logged, never shown in the terminal, never committed. Leave empty to use the local heuristic engine.
              </span>
            </label>
            <label className="field">
              <span>Model name</span>
              <input className="input mono" value={model} onChange={(e) => setModel(e.target.value)} placeholder="gemini-2.5-flash" spellCheck={false} />
              <span className="help">If you get a 404, try another Gemini model name (for example gemini-2.0-flash).</span>
            </label>
            <div className="row">
              <Button variant="secondary" onClick={test} busy={testing} disabledReason={!key.trim() && !ENV_KEY ? 'Paste a key first' : undefined}>Test Connection</Button>
              {result && <span role="status" className={`pill ${result.ok ? 'chip ok' : 'chip bad'}`} style={{ whiteSpace: 'normal', textTransform: 'none' }}>{result.text}</span>}
            </div>
          </section>

          <section className="stack">
            <div className="label">Demo</div>
            <div className="field">
              <span>Step speed (7-step panel)</span>
              <div className="seg" role="tablist" aria-label="Step speed">
                {(Object.keys(SPEED_MS) as Settings['speed'][]).map((sp) => (
                  <button key={sp} role="tab" aria-selected={settings.speed === sp} type="button" onClick={() => update({ speed: sp })}>
                    {sp[0].toUpperCase() + sp.slice(1)} · {SPEED_MS[sp]}ms
                  </button>
                ))}
              </div>
            </div>
            <Switch checked={settings.rememberEngine} onChange={(v) => update({ rememberEngine: v })} label="Remember engine state after reload" />
          </section>

          <section className="stack">
            <div className="label">Data</div>
            <div className="row">
              <Button variant="neutral" onClick={() => setConfirmClear(true)}>Clear all data</Button>
              <span className="small muted">Removes events, alerts, audit ledger, settings (including the key) and session from this browser.</span>
            </div>
          </section>

          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button variant="secondary" onClick={close}>Cancel</Button>
            <Button onClick={save}>Save settings</Button>
          </div>
        </div>
      </Modal>
      <ConfirmModal open={confirmClear} onClose={() => setConfirmClear(false)} title="Clear all data?" confirmLabel="Yes, clear everything" onConfirm={clearAllData}
        body="This wipes everything Riskbyte stored in this browser, including your Gemini key, and reloads the app. It cannot be undone." />
    </>
  );
}
