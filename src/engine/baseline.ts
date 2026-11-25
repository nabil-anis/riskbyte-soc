import type { ClientId, Org, RiskEvent } from './types';

/**
 * Normal day-to-day telemetry that keeps flowing 24/7: logins from internal addresses,
 * DNS to well-known domains, everyday processes, small daytime payments.
 * None of it matches a detection rule, so the pipeline scans it and stays quiet.
 */
const pick = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)];
const n = (lo: number, hi: number) => lo + Math.floor(Math.random() * (hi - lo + 1));
const internalIp = () => `10.${n(0, 40)}.${n(0, 255)}.${n(2, 250)}`;

const HOSTS: Record<string, string[]> = {
  meezan: ['ibanking-web-01', 'ibanking-web-02', 'branch-ws-07', 'core-db-02', 'raast-gw-01', 'atm-ctrl-03', 'teller-ws-12'],
  shu: ['lms-web-01', 'admissions-web-01', 'lab-pc-04', 'lab-pc-18', 'campus-dc-01', 'research-fs-01'],
  contour: ['dev-ws-042', 'dev-ws-108', 'ci-build-01', 'git-srv-01', 'vpn-gw-01', 'payroll-app-01'],
};
const USERS: Record<string, string[]> = {
  meezan: ['staff.farooq', 'teller.amna', 'ops.batch', 'customer.ali', 'customer.sana'],
  shu: ['faculty.ahmed', 'faculty.sara', 'student.fatima', 'student.lab18', 'it.helpdesk'],
  contour: ['dev.hamza', 'dev.bilal', 'dev.usman', 'jenkins_svc', 'hr.maria'],
};
const GENERIC_HOSTS = ['web-01', 'ws-014', 'ws-021', 'fileserver-01', 'dc-01', 'mail-01'];
const GENERIC_USERS = ['user.finance', 'user.ops', 'user.hr', 'svc.backup', 'user.remote'];
const DOMAINS = ['microsoft.com', 'office365.com', 'google.com', 'github.com', 'windowsupdate.com', 'zoom.us', 'slack.com'];
const PROCS = ['chrome.exe', 'outlook.exe', 'teams.exe', 'code.exe', 'excel.exe', 'explorer.exe', 'svchost.exe'];

function one(org: ClientId, ts: string): Partial<RiskEvent> {
  const host = pick(HOSTS[org] ?? GENERIC_HOSTS);
  const user = pick(USERS[org] ?? GENERIC_USERS);
  const base = { client: org, ts, origin: 'ingest-api' as const };
  switch (n(0, 7)) {
    case 0: return { ...base, source: 'web', host, user, ip: internalIp(), action: 'login_success', message: `Login for ${user}` };
    case 1: return { ...base, source: 'gateway', host, action: 'dns_query', domain: pick(DOMAINS), message: 'DNS lookup' };
    case 2: { const p = pick(PROCS); return { ...base, source: 'endpoint', host, user, process: p, action: 'process_start', message: `${p} started` }; }
    case 3: return { ...base, source: 'syslog', host, user, ip: internalIp(), action: 'login_success', message: `sshd: Accepted publickey for ${user}` };
    case 4: return { ...base, source: 'vpn', host: 'vpn-gw-01', user, ip: internalIp(), meta: { geo: 'Baseline (Pakistan)' }, action: 'login_success', message: 'VPN session established' };
    case 5: return { ...base, source: 'web', host, user, ip: internalIp(), action: 'login_failed', message: `Failed login for ${user} (typo)` };
    case 6: return { ...base, source: 'endpoint', host, user, action: 'file_write', message: `Saved document (${n(12, 900)} KB)` };
    default: return org === 'meezan'
      ? { ...base, source: 'payments', host: 'raast-gw-01', user: 'ops.batch', ip: internalIp(), action: 'transfer', meta: { amount: n(500, 40000), hour: n(9, 17) }, message: 'Routine customer transfer' }
      : { ...base, source: 'gateway', host, action: 'net_connect', ip: internalIp(), message: 'Internal service connection' };
  }
}

export function baselineBatch(orgs: Org[], count = n(2, 6), now = Date.now()): Partial<RiskEvent>[] {
  if (!orgs.length) return [];
  return Array.from({ length: count }, (_, i) => one(pick(orgs).id, new Date(now - (count - i) * 300).toISOString()));
}
