import type { ClientId, EventSource } from './types';

/** Parses real log files into Riskbyte events: JSON / NDJSON, Linux auth.log (sshd, sudo, useradd) and generic syslog. */
export interface ParseResult {
  format: 'json' | 'ndjson' | 'syslog';
  events: Record<string, unknown>[];
  skipped: number;
}

const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
// "Nov 25 10:12:01 host prog[123]: message"  or RFC 5424/ISO "2026-11-25T10:12:01Z host prog: message"
const BSD = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[\d+\])?:\s*(.*)$/;
const ISO = /^(\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([^:\[\s]+)(?:\[\d+\])?:\s*(.*)$/;

function syslogTs(mon: string, day: string, h: string, m: string, s: string, now = new Date()): string {
  const d = new Date(now.getFullYear(), MONTHS[mon.toLowerCase()] ?? now.getMonth(), Number(day), Number(h), Number(m), Number(s));
  if (d.getTime() > now.getTime() + 86400_000) d.setFullYear(d.getFullYear() - 1);
  return d.toISOString();
}

/** Maps one syslog message to a Riskbyte event (action, user, ip). */
export function classifySyslog(prog: string, msg: string): { action: string; user?: string; ip?: string; source: EventSource; meta?: Record<string, string | number | boolean> } {
  const ip = msg.match(/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{3,})/i)?.[1] ?? msg.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)?.[1];
  const p = prog.toLowerCase();
  let m: RegExpMatchArray | null;
  if (p.startsWith('sshd')) {
    if ((m = msg.match(/Failed (?:password|publickey|keyboard-interactive\/pam) for (?:invalid user )?(\S+)/i))) return { action: 'login_failed', user: m[1], ip, source: 'syslog' };
    if ((m = msg.match(/Invalid user (\S+)/i))) return { action: 'login_failed', user: m[1], ip, source: 'syslog' };
    if ((m = msg.match(/Accepted (?:password|publickey|keyboard-interactive\/pam) for (\S+)/i))) return { action: 'login_success', user: m[1], ip, source: 'syslog' };
    if ((m = msg.match(/authentication failure;.*user=(\S+)/i))) return { action: 'login_failed', user: m[1], ip, source: 'syslog' };
  }
  if (p === 'sudo' && (m = msg.match(/^\s*(\S+)\s*:.*COMMAND=(.*)$/))) return { action: 'process_start', user: m[1], source: 'endpoint', meta: { sudo: true } };
  if ((p === 'useradd' || p === 'adduser') && (m = msg.match(/new user: name=([^,\s]+)/i))) return { action: 'user_created', user: m[1], source: 'syslog' };
  if ((p === 'usermod' || p === 'gpasswd') && (m = msg.match(/add '?([^' ]+)'? to (?:group|shadow group) '?(sudo|wheel|admin|root)'?/i))) return { action: 'user_created', user: m[1], source: 'syslog', meta: { privileged: true, group: m[2] } };
  if (/login|auth/.test(p) && /fail/i.test(msg)) return { action: 'login_failed', ip, source: 'syslog', user: msg.match(/user[= ](\S+)/i)?.[1] };
  return { action: 'syslog', ip, source: 'syslog' };
}

export function parseLogText(text: string, client: ClientId, now = new Date()): ParseResult {
  const trimmed = text.trim();
  if (!trimmed) return { format: 'syslog', events: [], skipped: 0 };
  if (trimmed.startsWith('[') || trimmed.startsWith('{"events"') || (trimmed.startsWith('{') && !trimmed.includes('\n'))) {
    try {
      const j = JSON.parse(trimmed);
      const arr = Array.isArray(j) ? j : Array.isArray(j?.events) ? j.events : [j];
      return { format: 'json', events: arr.map((e: Record<string, unknown>) => ({ client, source: 'syslog', action: 'event', message: '', ...e })), skipped: 0 };
    } catch { /* fall through */ }
  }
  const lines = trimmed.split(/\r?\n/);
  if (lines[0].trim().startsWith('{')) {
    const events: Record<string, unknown>[] = [];
    let skipped = 0;
    for (const l of lines) {
      try { events.push({ client, source: 'syslog', action: 'event', message: '', ...JSON.parse(l) }); } catch { skipped++; }
    }
    return { format: 'ndjson', events, skipped };
  }
  const events: Record<string, unknown>[] = [];
  let skipped = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    let ts: string, host: string, prog: string, msg: string;
    let m = line.match(BSD);
    if (m) { ts = syslogTs(m[1], m[2], m[3], m[4], m[5], now); host = m[6]; prog = m[7]; msg = m[8]; }
    else if ((m = line.match(ISO))) { ts = new Date(m[1]).toISOString(); host = m[2]; prog = m[3]; msg = m[4]; }
    else { skipped++; continue; }
    const c = classifySyslog(prog, msg);
    events.push({ client, ts, host, process: prog, message: msg.slice(0, 500), ...c, ...(c.user ? { user: c.user } : {}), ...(c.ip ? { ip: c.ip } : {}) });
  }
  return { format: 'syslog', events, skipped };
}
