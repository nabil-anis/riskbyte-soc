import { useEffect, useState } from 'react';
import { useStore, WORKSPACE_LABEL, WORKSPACE_ROLE } from '../store/store';
import { MAX_FAILED, MIN_PASSWORD, USERNAMES_DEFAULT } from './authDefaults';
import { Button, ConfirmModal, Modal, useTick } from './ui';

/** Sign-in / first-run account setup for a tier console. Passwords are PBKDF2-hashed in this browser. */
export function AuthGate() {
  useTick(1000);
  const prompt = useStore((s) => s.authPrompt);
  const accounts = useStore((s) => s.accounts);
  const client = useStore((s) => s.client);
  const set = useStore((s) => s.set);
  const createAccount = useStore((s) => s.createAccount);
  const login = useStore((s) => s.login);
  const completeReset = useStore((s) => s.completeReset);
  const deleteAccount = useStore((s) => s.deleteAccount);
  const role = prompt ? WORKSPACE_ROLE[prompt.ws] : null;
  const acc = role ? accounts[role] : undefined;
  const [username, setUsername] = useState('');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [newPw, setNewPw] = useState('');
  const [mode, setMode] = useState<'setup' | 'login' | 'reset'>('login');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (!role) return;
    setMode(accounts[role] ? 'login' : 'setup');
    setUsername(accounts[role]?.username ?? USERNAMES_DEFAULT[role]);
    setPw(''); setPw2(''); setNewPw(''); setError(null);
  }, [role, !!acc]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!prompt || !role) return null;
  const close = () => set({ authPrompt: null });
  const locked = acc?.lockedUntil && acc.lockedUntil > Date.now() ? Math.ceil((acc.lockedUntil - Date.now()) / 1000) : 0;

  const submit = async () => {
    setBusy(true); setError(null);
    if (mode === 'setup') {
      if (pw !== pw2) { setBusy(false); setError('Passwords do not match'); return; }
      const r = await createAccount(role, username, pw);
      if (!r.ok) setError(r.error);
    } else if (mode === 'login') {
      const r = await login(role, username, pw);
      if (!r.ok) {
        if (r.needReset) { setMode('reset'); setError(r.error); } else setError(r.error);
        setPw(r.needReset ? pw : '');
      }
    } else {
      if (newPw !== pw2) { setBusy(false); setError('New passwords do not match'); return; }
      const r = await completeReset(role, username, pw, newPw);
      if (!r.ok) setError(r.error);
    }
    setBusy(false);
  };

  return (
    <Modal open onClose={close} label={`Sign in to ${WORKSPACE_LABEL[prompt.ws]}`}
      title={<div><div className="label">{mode === 'setup' ? 'First-time setup' : mode === 'reset' ? 'Credential reset required' : 'Sign in'}</div><h3 style={{ marginTop: 6 }}>{WORKSPACE_LABEL[prompt.ws]}</h3></div>}>
      <form className="stack-lg" onSubmit={(e) => { e.preventDefault(); submit(); }}>
        {mode === 'setup' && <p className="small muted">No account exists for this tier yet. Create one: the password is hashed with PBKDF2-SHA256 (150,000 iterations) and stored in this browser. Every sign-in, failure and lockout is logged and audited.</p>}
        {mode === 'reset' && <p className="small muted">An analyst approved <code>reset_password</code> for this account. Enter your current password and choose a new one.</p>}
        <label className="field"><span>Username</span><input className="input mono" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" spellCheck={false} disabled={mode === 'reset'} /></label>
        <label className="field"><span>{mode === 'reset' ? 'Current password' : 'Password'}</span><input className="input" type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete={mode === 'setup' ? 'new-password' : 'current-password'} /></label>
        {mode === 'reset' && <label className="field"><span>New password</span><input className="input" type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} autoComplete="new-password" /></label>}
        {(mode === 'setup' || mode === 'reset') && <label className="field"><span>Confirm {mode === 'reset' ? 'new ' : ''}password</span><input className="input" type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" /><span className="help">At least {MIN_PASSWORD} characters with letters and numbers.</span></label>}
        {error && <div className="banner bad small" role="alert">{error}</div>}
        {locked > 0 && <div className="banner bad small" role="status">Locked after {MAX_FAILED} failed attempts. Try again in {locked}s.</div>}
        <div className="small muted">Connecting from <b className="mono">{client?.ip ?? '…'}</b>{client?.city || client?.country ? ` · ${[client?.city, client?.country].filter(Boolean).join(', ')}` : ''}. This attempt is recorded in the platform's live logs.</div>
        <div className="row" style={{ justifyContent: 'space-between' }}>
          {mode === 'login' ? <button type="button" className="link-btn" onClick={() => setConfirmDelete(true)}>Can't sign in? Delete this account</button> : <span />}
          <div className="row">
            <Button variant="secondary" onClick={close}>Cancel</Button>
            <Button type="submit" busy={busy} disabledReason={locked > 0 ? `Locked for ${locked}s` : null}>{mode === 'setup' ? 'Create account & sign in' : mode === 'reset' ? 'Change password & sign in' : 'Sign in'}</Button>
          </div>
        </div>
      </form>
      <ConfirmModal open={confirmDelete} onClose={() => setConfirmDelete(false)} title="Delete this tier's account?" confirmLabel="Delete account"
        onConfirm={() => deleteAccount(role)} body="This removes the stored account for this tier so a new one can be created. The deletion is written to the audit ledger with your IP address." />
    </Modal>
  );
}
