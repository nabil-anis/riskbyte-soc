import type { Role } from './types';

/** Simulated bearer tokens. This is a classroom simulation, not real authentication. */
export const TOKENS: Record<Role, string> = {
  ingest: 'dev-ingest',
  analyst: 'dev-analyst',
  admin: 'dev-admin',
};

export const USERNAMES: Record<Role, string> = {
  ingest: 'ingest.agent',
  analyst: 'soc.analyst',
  admin: 'soc.admin',
};

/** Constant-time string comparison (avoids leaking length of matching prefix through timing). */
export function constantTimeEqual(a: string, b: string): boolean {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

export function roleForToken(token: string | undefined): Role | undefined {
  if (!token) return undefined;
  let found: Role | undefined;
  // Check every token (no early exit) to keep timing uniform.
  (Object.keys(TOKENS) as Role[]).forEach((r) => {
    if (constantTimeEqual(token, TOKENS[r])) found = r;
  });
  return found;
}

export const actorFor = (role: Role) => `${role}:${USERNAMES[role]}`;
