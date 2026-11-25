import type { Role } from './types';
import { sha256Fallback } from './sha256';

/** Console accounts with PBKDF2-SHA256 password hashes, lockout and expiring sessions (stored in this browser). */
export interface Account {
  role: Role;
  username: string;
  salt: string;
  hash: string;
  algo: 'pbkdf2-sha256' | 'sha256-iter';
  iterations: number;
  createdAt: string;
  passwordChangedAt: string;
  lastLoginAt?: string;
  lastLoginIp?: string;
  failed: number;
  lockedUntil?: number;
}

export interface Session { role: Role; username: string; startedAt: number; expiresAt: number }

export const ACCOUNTS_KEY = 'riskbyte.accounts.v1';
export const SESSIONS_KEY = 'riskbyte.sessions.v1';
export const SESSION_HOURS = 8;
export const MAX_FAILED = 5;
export const LOCK_MS = 60_000;
export const MIN_PASSWORD = 8;
const ITERATIONS = 150_000;

const hex = (b: ArrayBuffer | Uint8Array) => Array.from(b instanceof Uint8Array ? b : new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));

function randomSalt(): string {
  const b = new Uint8Array(16);
  globalThis.crypto?.getRandomValues ? globalThis.crypto.getRandomValues(b) : b.forEach((_, i) => (b[i] = Math.floor(Math.random() * 256)));
  return hex(b);
}

const canPbkdf2 = () => !!globalThis.crypto?.subtle && (typeof window === 'undefined' || window.isSecureContext !== false);

async function derive(password: string, salt: string, algo: Account['algo'], iterations: number): Promise<string> {
  if (algo === 'pbkdf2-sha256') {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(salt), iterations }, key, 256);
    return hex(bits);
  }
  // Fallback for insecure contexts (file://): iterated salted SHA-256.
  let h = sha256Fallback(salt + password);
  for (let i = 1; i < iterations; i++) h = sha256Fallback(h + salt);
  return h;
}

/** Constant-time comparison of two hex strings. */
function same(a: string, b: string) {
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

export async function hashPassword(password: string): Promise<Pick<Account, 'salt' | 'hash' | 'algo' | 'iterations'>> {
  const salt = randomSalt();
  const algo: Account['algo'] = canPbkdf2() ? 'pbkdf2-sha256' : 'sha256-iter';
  const iterations = algo === 'pbkdf2-sha256' ? ITERATIONS : 4000;
  return { salt, algo, iterations, hash: await derive(password, salt, algo, iterations) };
}

export async function verifyPassword(acc: Account, password: string): Promise<boolean> {
  return same(await derive(password, acc.salt, acc.algo, acc.iterations), acc.hash);
}

export function passwordProblem(pw: string): string | null {
  if (pw.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters`;
  if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) return 'Use both letters and numbers';
  return null;
}

function read<T>(key: string, fallback: T): T {
  try { const r = localStorage.getItem(key); return r ? (JSON.parse(r) as T) : fallback; } catch { return fallback; }
}
function write(key: string, v: unknown) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* ignore */ }
}

export const loadAccounts = (): Partial<Record<Role, Account>> => read(ACCOUNTS_KEY, {});
export const saveAccounts = (a: Partial<Record<Role, Account>>) => write(ACCOUNTS_KEY, a);
export function loadSessions(now = Date.now()): Partial<Record<Role, Session>> {
  const s = read<Partial<Record<Role, Session>>>(SESSIONS_KEY, {});
  for (const r of Object.keys(s) as Role[]) if (!s[r] || s[r]!.expiresAt <= now) delete s[r];
  return s;
}
export const saveSessions = (s: Partial<Record<Role, Session>>) => write(SESSIONS_KEY, s);
export const newSession = (role: Role, username: string, now = Date.now()): Session => ({ role, username, startedAt: now, expiresAt: now + SESSION_HOURS * 3600_000 });
