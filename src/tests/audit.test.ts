import { describe, it, expect } from 'vitest';
import { appendBlock, genesis, verifyChain, tamper, repairChain, GENESIS_PREV } from '../engine/audit';
import type { AuditBlock } from '../engine/types';

async function build(n: number) {
  let chain: AuditBlock[] = [await genesis('2026-11-25T00:00:00.000Z')];
  for (let i = 0; i < n; i++) chain = (await appendBlock(chain, { client: 'meezan', actor: 'analyst:soc.analyst', kind: 'test', detail: `entry ${i}` })).chain;
  return chain;
}

describe('audit ledger', () => {
  it('genesis block is correct and chain verifies', async () => {
    const chain = await build(5);
    expect(chain[0].prevHash).toBe(GENESIS_PREV);
    expect(chain[0].kind).toBe('ledger.genesis');
    expect(chain[3].prevHash).toBe(chain[2].hash);
    expect((await verifyChain(chain)).intact).toBe(true);
  });
  it('modifying any field breaks verification at that index', async () => {
    const chain = await build(5);
    for (const field of ['detail', 'actor', 'kind', 'ts'] as const) {
      for (const idx of [1, 3, 5]) {
        const bad = chain.map((b) => (b.index === idx ? { ...b, [field]: b[field] + 'x' } : b));
        const s = await verifyChain(bad);
        expect(s.intact).toBe(false);
        expect(s.brokenAt).toBe(idx);
      }
    }
  });
  it('tamper simulation then repair restores integrity', async () => {
    const chain = await build(6);
    const { chain: t, index } = tamper(chain);
    const s = await verifyChain(t);
    expect(s.intact).toBe(false);
    expect(s.brokenAt).toBe(index);
    const { chain: fixed, from } = await repairChain(t, 'admin:soc.admin');
    expect(from).toBe(index);
    expect((await verifyChain(fixed)).intact).toBe(true);
    expect(fixed[fixed.length - 1].kind).toBe('ledger.repaired');
  });
});
