import type { AuditBlock, AuditStatus, ClientId } from './types';
import { sha256 } from './sha256';

export const GENESIS_PREV = '0'.repeat(64);

export function hashInput(prevHash: string, ts: string, actor: string, kind: string, detail: string): string {
  return prevHash + ts + actor + kind + detail;
}

export async function computeHash(b: Pick<AuditBlock, 'prevHash' | 'ts' | 'actor' | 'kind' | 'detail'>): Promise<string> {
  return sha256(hashInput(b.prevHash, b.ts, b.actor, b.kind, b.detail));
}

export async function genesis(ts = new Date().toISOString()): Promise<AuditBlock> {
  const base = { index: 0, ts, client: 'system' as const, actor: 'system', kind: 'ledger.genesis', detail: 'Riskbyte audit ledger created', prevHash: GENESIS_PREV };
  return { ...base, hash: await computeHash(base) };
}

export interface AppendInput {
  client: ClientId | 'system';
  actor: string;
  kind: string;
  detail: string;
  alertId?: string;
  ts?: string;
}

/** Returns a new chain with the block appended (does not mutate). */
export async function appendBlock(chain: AuditBlock[], input: AppendInput): Promise<{ chain: AuditBlock[]; block: AuditBlock }> {
  const prev = chain[chain.length - 1];
  const base = {
    index: prev ? prev.index + 1 : 0,
    ts: input.ts ?? new Date().toISOString(),
    client: input.client,
    actor: input.actor,
    kind: input.kind,
    alertId: input.alertId,
    detail: input.detail,
    prevHash: prev ? prev.hash : GENESIS_PREV,
  };
  const block: AuditBlock = { ...base, hash: await computeHash(base) };
  return { chain: [...chain, block], block };
}

/** Verifies every block's hash and link. Reports the first broken block index. */
export async function verifyChain(chain: AuditBlock[]): Promise<AuditStatus> {
  const checkedAt = new Date().toISOString();
  for (let i = 0; i < chain.length; i++) {
    const b = chain[i];
    const expectedPrev = i === 0 ? GENESIS_PREV : chain[i - 1].hash;
    if (b.prevHash !== expectedPrev) return { intact: false, brokenAt: b.index, blocks: chain.length, checkedAt };
    const h = await computeHash(b);
    if (h !== b.hash) return { intact: false, brokenAt: b.index, blocks: chain.length, checkedAt };
  }
  return { intact: true, blocks: chain.length, checkedAt };
}

/** Simulated tampering: edit a block's detail in place WITHOUT rehashing. */
export function tamper(chain: AuditBlock[], index?: number): { chain: AuditBlock[]; index: number } {
  if (chain.length === 0) return { chain, index: -1 };
  const target = index ?? (chain.length > 2 ? Math.max(1, chain.length - 2) : chain.length - 1);
  const next = chain.map((b) => (b.index === target ? { ...b, detail: b.detail + ' [edited by intruder]' } : b));
  return { chain: next, index: target };
}

/** Recomputes hashes from the first broken block onward, then appends ledger.repaired. */
export async function repairChain(chain: AuditBlock[], actor: string): Promise<{ chain: AuditBlock[]; from: number }> {
  const status = await verifyChain(chain);
  const from = status.intact ? chain.length : status.brokenAt!;
  const fixed: AuditBlock[] = [];
  for (let i = 0; i < chain.length; i++) {
    const b = chain[i];
    if (i < from) { fixed.push(b); continue; }
    const prevHash = i === 0 ? GENESIS_PREV : fixed[i - 1].hash;
    const base = { ...b, prevHash };
    fixed.push({ ...base, hash: await computeHash(base) });
  }
  const { chain: out } = await appendBlock(fixed, {
    client: 'system',
    actor,
    kind: 'ledger.repaired',
    detail: status.intact ? 'Repair requested; chain already intact' : `Chain rebuilt from block #${from}; tampering acknowledged`,
  });
  return { chain: out, from };
}
