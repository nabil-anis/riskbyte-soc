import { describe, it, expect } from 'vitest';
import { attachToCase } from '../engine/cases';

describe('cases', () => {
  it('groups alerts by client+entity and takes max severity', () => {
    let r = attachToCase([], { client: 'shu', entity: 'lab-pc-18', entityType: 'host', severity: 'MEDIUM', alertId: 'A-1', ts: 't' }, 1);
    expect(r.created).toBe(true);
    r = attachToCase(r.cases, { client: 'shu', entity: 'lab-pc-18', entityType: 'host', severity: 'CRITICAL', alertId: 'A-2', ts: 't' }, 2);
    expect(r.created).toBe(false);
    r = attachToCase(r.cases, { client: 'shu', entity: 'lab-pc-18', entityType: 'host', severity: 'LOW', alertId: 'A-3', ts: 't' }, 2);
    expect(r.cases).toHaveLength(1);
    expect(r.cases[0].severity).toBe('CRITICAL');
    expect(r.cases[0].alertIds).toEqual(['A-1', 'A-2', 'A-3']);
    r = attachToCase(r.cases, { client: 'meezan', entity: 'lab-pc-18', entityType: 'host', severity: 'LOW', alertId: 'A-4', ts: 't' }, 2);
    expect(r.cases).toHaveLength(2);
  });
});
