import { describe, it, expect } from 'vitest';
import { sha256, sha256Fallback } from '../engine/sha256';

describe('sha256', () => {
  it('matches known vectors (fallback)', () => {
    expect(sha256Fallback('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Fallback('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256Fallback('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });
  it('fallback matches crypto.subtle for many inputs', async () => {
    const inputs = ['Riskbyte', 'ünïcødé ✓ 🛡️', 'x'.repeat(55), 'y'.repeat(56), 'z'.repeat(64), 'q'.repeat(1000)];
    for (const s of inputs) expect(sha256Fallback(s)).toBe(await sha256(s));
  });
});
