import { useStore } from '../store/store';

export const ENGINE_OFF = 'Turn the Engine on first';

/** Why an analyst action (approve/dismiss) is disabled, or null if allowed. */
export function useDecisionGate(): string | null {
  const on = useStore((s) => s.engineOn);
  const role = useStore((s) => s.session?.role);
  if (role === 'ingest') return "Your role (Telemetry Ingest) can't approve or dismiss";
  if (!on) return ENGINE_OFF;
  return null;
}

export function useEngineGate(): string | null {
  const on = useStore((s) => s.engineOn);
  return on ? null : ENGINE_OFF;
}

export function useAdminGate(): string | null {
  const role = useStore((s) => s.session?.role);
  return role === 'admin' ? null : 'Administrator only. Switch role from the badge in the top bar.';
}
