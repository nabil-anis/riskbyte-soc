import type { Case, ClientId, Severity } from './types';
import { maxSeverity } from './types';

export function caseId(n: number) {
  return `C-${String(n).padStart(4, '0')}`;
}

/** Attach to the open case for (client, entity) or open a new one. Case severity = max of its alerts. */
export function attachToCase(
  cases: Case[],
  input: { client: ClientId; entity: string; entityType: Case['entityType']; severity: Severity; alertId: string; ts: string },
  nextNumber: number,
): { cases: Case[]; caseId: string; created: boolean } {
  const existing = cases.find((c) => c.status === 'open' && c.client === input.client && c.entity === input.entity);
  if (existing) {
    const updated: Case = { ...existing, severity: maxSeverity(existing.severity, input.severity), alertIds: [...existing.alertIds, input.alertId] };
    return { cases: cases.map((c) => (c.id === existing.id ? updated : c)), caseId: existing.id, created: false };
  }
  const c: Case = {
    id: caseId(nextNumber),
    client: input.client,
    entity: input.entity,
    entityType: input.entityType,
    severity: input.severity,
    status: 'open',
    openedAt: input.ts,
    alertIds: [input.alertId],
  };
  return { cases: [...cases, c], caseId: c.id, created: true };
}

/** A case closes once every alert in it has been executed or dismissed. */
export function refreshCaseStatus(cases: Case[], alertStatus: (id: string) => string | undefined): Case[] {
  return cases.map((c) => {
    const done = c.alertIds.every((id) => ['executed', 'dismissed'].includes(alertStatus(id) ?? ''));
    return { ...c, status: done ? 'closed' : 'open' };
  });
}
