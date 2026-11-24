import { useEffect, useRef, useState, type ReactNode, type MouseEvent } from 'react';
import type { Alert, Case, ClientId, Severity, Verdict, Triage } from '../engine/types';
import { clientById } from '../data/clients';
import { useStore } from '../store/store';

export function SeverityBadge({ sev }: { sev: Severity }) {
  return <span className={`pill sev-${sev}`}>{sev}</span>;
}
export function VerdictPill({ v }: { v: Verdict }) {
  return <span className={`pill v-${v}`}>{v}</span>;
}
export function StatusBadge({ status }: { status: Alert['status'] | Case['status'] }) {
  return <span className={`pill st-${status}`}>{status}</span>;
}
export function ClientBadge({ client }: { client: ClientId | 'system' }) {
  return <span className="pill client-pill">{client === 'system' ? 'System' : clientById(client).name}</span>;
}
export function EngineBadge({ t }: { t: Triage }) {
  const text = t.provider === 'gemini' ? `gemini · ${t.model}` : t.fallbackReason ? `heuristic (Gemini unavailable: ${t.fallbackReason})` : 'heuristic';
  return <span className={`pill engine-badge ${t.fallbackReason ? 'fallback' : ''}`}>{text}</span>;
}
export function RedactionChip({ t }: { t: Triage }) {
  if (!t.redacted) return <span className="pill chip" title="Heuristic triage runs locally; nothing leaves the browser, so no redaction is needed.">Local only · no data sent</span>;
  const c = t.redactionCounts ?? {};
  const tip = `Tokens sent instead of real values: ${Object.entries(c).filter(([, n]) => n).map(([k, n]) => `${n} ${k.toLowerCase()}${n > 1 ? 's' : ''}`).join(', ') || 'none needed'}`;
  return <span className="tip" data-tip={tip}><span className="pill chip ok" tabIndex={0} aria-label={`Redaction applied. ${tip}`}>🛡 Redaction applied</span></span>;
}

export interface BtnProps {
  children: ReactNode;
  onClick?: (e: MouseEvent<HTMLButtonElement>) => void;
  variant?: 'primary' | 'secondary' | 'neutral' | 'dark';
  size?: 'sm';
  disabledReason?: string | false | null;
  busy?: boolean;
  className?: string;
  type?: 'button' | 'submit';
  ariaLabel?: string;
}

/** Disabled buttons stay focusable and explain why via a tooltip. */
export function Button({ children, onClick, variant = 'primary', size, disabledReason, busy, className = '', type = 'button', ariaLabel }: BtnProps) {
  const disabled = !!disabledReason || busy;
  const btn = (
    <button
      type={type}
      className={`btn btn-${variant} ${size === 'sm' ? 'btn-sm' : ''} ${className}`}
      aria-disabled={disabled || undefined}
      aria-label={ariaLabel}
      title={disabledReason || undefined}
      onClick={(e) => {
        if (disabled) { e.preventDefault(); return; }
        onClick?.(e);
      }}
    >
      {busy && <span className="spinner" aria-hidden />}
      {children}
    </button>
  );
  return disabledReason ? <span className="tip" data-tip={disabledReason}>{btn}</span> : btn;
}

export function Switch({ checked, onChange, label, disabledReason }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabledReason?: string | false }) {
  const el = (
    <button type="button" role="switch" aria-checked={checked} aria-disabled={!!disabledReason || undefined} className="switch" onClick={() => !disabledReason && onChange(!checked)}>
      <span className="track" aria-hidden />
      {label}
    </button>
  );
  return disabledReason ? <span className="tip" data-tip={disabledReason}>{el}</span> : el;
}

export function EmptyState({ icon, title, children }: { icon: string; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="big" aria-hidden>{icon}</div>
      <h3>{title}</h3>
      {children && <div className="muted">{children}</div>}
    </div>
  );
}

export function HashChip({ hash, label = 'hash' }: { hash: string; label?: string }) {
  const toast = useStore((s) => s.toast);
  return (
    <span className="hash-chip" title={hash}>
      <span>{label} {hash.slice(0, 10)}…</span>
      <button type="button" onClick={() => copy(hash).then(() => toast('Hash copied'))} aria-label={`Copy full ${label}`}>copy</button>
    </span>
  );
}

export async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

/** Modal or drawer with Esc to close, focus trap, and focus restore. */
export function Modal({ open, onClose, title, label, children, kind = 'modal', wide }: { open: boolean; onClose: () => void; title: ReactNode; label?: string; children: ReactNode; kind?: 'modal' | 'drawer'; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    const focusables = () => Array.from(el?.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])') ?? []).filter((x) => !x.hasAttribute('disabled'));
    setTimeout(() => (focusables()[1] ?? focusables()[0])?.focus(), 30);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onClose(); }
      if (e.key === 'Tab') {
        const f = focusables();
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', onKey, true);
    return () => { document.removeEventListener('keydown', onKey, true); prev?.focus?.(); };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className={`overlay ${kind === 'drawer' ? 'right' : ''}`} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className={`${kind} ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={label ?? (typeof title === 'string' ? title : 'Dialog')}>
        <div className="modal-head">
          <div className="grow">{typeof title === 'string' ? <h3>{title}</h3> : title}</div>
          <button className="close-x" type="button" onClick={onClose} aria-label="Close">×</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function ConfirmModal({ open, title, body, confirmLabel, onConfirm, onClose }: { open: boolean; title: string; body: ReactNode; confirmLabel: string; onConfirm: () => void; onClose: () => void }) {
  return (
    <Modal open={open} onClose={onClose} title={title}>
      <div className="stack-lg">
        <div className="muted">{body}</div>
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={() => { onConfirm(); onClose(); }}>{confirmLabel}</Button>
        </div>
      </div>
    </Modal>
  );
}

export function Toasts() {
  const toasts = useStore((s) => s.toasts);
  return (
    <div className="toasts" aria-live="polite" role="status">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.tone ?? ''}`}><span className="tdot" aria-hidden />{t.text}</div>
      ))}
    </div>
  );
}

export function relTime(iso: string, now = Date.now()) {
  const s = Math.round((now - Date.parse(iso)) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const fmtTime = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
export const fmtDateTime = (iso: string) => new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });

/** Re-render every `ms` (for relative times and countdowns). */
export function useTick(ms = 1000) {
  const [, setN] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setN((n) => n + 1), ms);
    return () => clearInterval(id);
  }, [ms]);
}

export function TriageView({ t, compact }: { t: Triage; compact?: boolean }) {
  return (
    <div className="stack-lg">
      <div className="row"><EngineBadge t={t} /><VerdictPill v={t.verdict} /><RedactionChip t={t} /><span className="pill chip">{t.ms} ms</span></div>
      <div className="conf">
        <div>
          <div className="label">Confidence</div>
          <div className="num" aria-label={`Confidence ${t.confidence} percent`}>{t.confidence}<span style={{ fontSize: '0.45em' }}>%</span></div>
        </div>
        <div className="grow" style={{ paddingBottom: 10 }}><div className="bar"><span style={{ width: `${t.confidence}%` }} /></div></div>
      </div>
      <p style={{ fontSize: compact ? 14.5 : 16 }}>{t.summary}</p>
      <div>
        <div className="label" style={{ marginBottom: 8 }}>Investigation steps</div>
        <ol className="steps">{t.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
      </div>
    </div>
  );
}
