import type { Rule, RiskEvent } from '../engine/types';
import { FLAGGED_PHISHING_DOMAINS } from './indicators';
import { isUntrustedIp, lookup } from '../engine/intel';

const t = (e: RiskEvent) => new Date(e.ts).getTime();
const msg = (e: RiskEvent) => (e.message || '').toLowerCase();
const proc = (e: RiskEvent) => (e.process || '').toLowerCase();
const within = (a: RiskEvent, b: RiskEvent, sec: number) => Math.abs(t(a) - t(b)) <= sec * 1000;

const yaml = (o: {
  title: string; id: string; description: string; logsource: string; selection: string;
  timeframe?: string; condition: string; level: string; tags: string[]; fp: string[];
}) =>
  `title: ${o.title}
id: ${o.id}
status: stable
description: ${o.description}
logsource: { ${o.logsource} }
detection:
  selection: { ${o.selection} }${o.timeframe ? `\n  timeframe: ${o.timeframe}` : ''}
  condition: ${o.condition}
level: ${o.level}
tags: [${o.tags.join(', ')}]
falsepositives: [${o.fp.join(', ')}]`;

export const RULES: Rule[] = [
  {
    id: 'rb-001', title: 'Repeated failed logins (brute force)', severity: 'MEDIUM', mitre: 'T1110', action: 'block_ip',
    description: 'Five or more failed logins from one IP inside 30 seconds',
    plain: 'Someone is guessing passwords over and over from the same address.',
    windowSec: 30, threshold: 5, groupBy: 'ip', entity: 'ip', target: 'ip',
    yaml: yaml({ title: 'Repeated failed logins (brute force)', id: 'rb-001', description: 'Five or more failed logins from one IP inside 30 seconds', logsource: 'category: authentication', selection: 'action: login_failed', timeframe: '30s', condition: 'selection | count(ip) by ip >= 5', level: 'medium', tags: ['attack.credential_access', 'attack.t1110'], fp: ['Users who forgot a password'] }),
    match: (e, w) => {
      if (e.action !== 'login_failed' || !e.ip) return null;
      const hits = w.filter((x) => x.action === 'login_failed' && x.ip === e.ip && x.client === e.client && t(x) <= t(e) && t(e) - t(x) <= 30_000);
      return hits.length >= 5 ? hits : null;
    },
  },
  {
    id: 'rb-002', title: 'Encoded PowerShell execution', severity: 'HIGH', mitre: 'T1059.001', action: 'isolate_host',
    description: 'PowerShell launched with an encoded (obfuscated) command',
    plain: 'A script was started in a disguised form, a common trick to hide what it does.',
    entity: 'host', target: 'host',
    yaml: yaml({ title: 'Encoded PowerShell execution', id: 'rb-002', description: 'PowerShell launched with -enc / -EncodedCommand', logsource: 'category: process_creation, product: windows', selection: "Image|endswith: 'powershell.exe', CommandLine|contains: ['-enc', '-EncodedCommand']", condition: 'selection', level: 'high', tags: ['attack.execution', 'attack.t1059.001'], fp: ['Admin scripts that use encoding legitimately'] }),
    match: (e) => (proc(e).includes('powershell') && /(^|\s)-(enc|encodedcommand)\b/i.test(e.message) ? [e] : null),
  },
  {
    id: 'rb-003', title: 'Scheduled task persistence', severity: 'MEDIUM', mitre: 'T1053.005', action: 'isolate_host',
    description: 'A scheduled task is created that runs a script from a user-writable path',
    plain: 'Something set itself up to run again automatically, so it survives a reboot.',
    entity: 'host', target: 'host',
    yaml: yaml({ title: 'Scheduled task persistence', id: 'rb-003', description: 'schtasks /create pointing at a script in a user path', logsource: 'category: process_creation, product: windows', selection: "Image|endswith: 'schtasks.exe', CommandLine|contains|all: ['/create', '\\\\Users\\\\']", condition: 'selection', level: 'medium', tags: ['attack.persistence', 'attack.t1053.005'], fp: ['Software updaters'] }),
    match: (e) =>
      proc(e).includes('schtasks') && /\/create/i.test(e.message) && /(\\users\\|appdata|\\temp\\|downloads).*\.(ps1|bat|vbs|js|cmd|exe)/i.test(e.message) ? [e] : null,
  },
  {
    id: 'rb-004', title: 'Credential dumping tool or LSASS access', severity: 'CRITICAL', mitre: 'T1003', action: 'isolate_host',
    description: 'Access to LSASS memory or a known credential dumper name appears',
    plain: 'Something is trying to read saved passwords out of Windows memory.',
    entity: 'host', target: 'host',
    yaml: yaml({ title: 'Credential dumping tool or LSASS access', id: 'rb-004', description: 'LSASS memory access or known dumper tool names', logsource: 'category: process_access, product: windows', selection: "TargetImage|endswith: 'lsass.exe' OR CommandLine|contains: ['mimikatz', 'sekurlsa', 'procdump']", condition: 'selection', level: 'critical', tags: ['attack.credential_access', 'attack.t1003'], fp: ['Security tools and EDR agents'] }),
    match: (e) => (/lsass|mimikatz|sekurlsa|procdump/.test(msg(e)) || /mimikatz|procdump/.test(proc(e)) ? [e] : null),
  },
  {
    id: 'rb-005', title: 'New privileged account created', severity: 'HIGH', mitre: 'T1136', action: 'disable_user',
    description: 'A new account is created with administrator privileges',
    plain: 'A brand-new admin account appeared, which attackers use as a back door.',
    entity: 'user', target: 'user',
    yaml: yaml({ title: 'New privileged account created', id: 'rb-005', description: 'user_created with privileged=true', logsource: 'category: iam', selection: 'action: user_created, privileged: true', condition: 'selection', level: 'high', tags: ['attack.persistence', 'attack.t1136'], fp: ['Planned admin onboarding'] }),
    match: (e) => (e.action === 'user_created' && (e.meta?.privileged === true || e.meta?.privileged === 'true') ? [e] : null),
  },
  {
    id: 'rb-006', title: 'Phishing link click then external login', severity: 'HIGH', mitre: 'T1566.002', action: 'reset_password',
    description: 'A user clicks a flagged phishing link, then logs in from an untrusted IP within 10 minutes',
    plain: 'Someone clicked a fake login link and, moments later, their account was used from outside.',
    windowSec: 600, groupBy: 'user', entity: 'user', target: 'user',
    yaml: yaml({ title: 'Phishing link click then external login', id: 'rb-006', description: 'link_click on flagged domain followed by login_success from untrusted IP', logsource: 'category: proxy, authentication', selection: 'click: { action: link_click, domain|in: flagged }, login: { action: login_success, ip|untrusted: true }', timeframe: '10m', condition: 'click | near login by user', level: 'high', tags: ['attack.initial_access', 'attack.t1566.002'], fp: ['Security awareness phishing tests'] }),
    match: (e, w) => {
      if (e.action !== 'login_success' || !e.user || !isUntrustedIp(e.ip)) return null;
      const click = w.find(
        (x) => x.action === 'link_click' && x.user === e.user && x.client === e.client && !!x.domain &&
          FLAGGED_PHISHING_DOMAINS.includes(x.domain) && t(x) <= t(e) && t(e) - t(x) <= 600_000,
      );
      return click ? [click, e] : null;
    },
  },
  {
    id: 'rb-007', title: 'Shadow copy deletion (ransomware)', severity: 'CRITICAL', mitre: 'T1490', action: 'isolate_host',
    description: 'Windows backup copies are deleted, or files are renamed in a burst',
    plain: 'Something is deleting backups and scrambling files, the classic ransomware pattern.',
    entity: 'host', target: 'host',
    yaml: yaml({ title: 'Shadow copy deletion (ransomware)', id: 'rb-007', description: 'vssadmin delete shadows, or bulk file rename burst', logsource: 'category: process_creation, file_event', selection: "CommandLine|contains: 'vssadmin delete shadows' OR (action: file_rename_bulk, count >= 500)", condition: 'selection', level: 'critical', tags: ['attack.impact', 'attack.t1490'], fp: ['Backup software maintenance'] }),
    match: (e) => (/vssadmin(\.exe)?\s+delete\s+shadows/.test(msg(e)) || (e.action === 'file_rename_bulk' && Number(e.meta?.count ?? 0) >= 500) ? [e] : null),
  },
  {
    id: 'rb-008', title: 'Anomalous geographic login', severity: 'HIGH', mitre: 'T1078', action: 'disable_user',
    description: 'VPN login from an IP or location outside the user baseline',
    plain: 'A staff account logged in from a country it normally never uses.',
    entity: 'user', target: 'user',
    yaml: yaml({ title: 'Anomalous geographic login', id: 'rb-008', description: 'login_success via VPN from outside the baseline geography', logsource: 'category: vpn', selection: 'action: login_success, source: vpn', condition: 'selection and geo not in baseline', level: 'high', tags: ['attack.defense_evasion', 'attack.t1078'], fp: ['Travelling staff without a travel notice'] }),
    match: (e) => {
      if (e.action !== 'login_success' || e.source !== 'vpn' || !e.user) return null;
      const geo = String(e.meta?.geo ?? '');
      const foreign = /^foreign/i.test(geo) || (!geo && !!lookup(e.ip));
      return foreign && isUntrustedIp(e.ip) ? [e] : null;
    },
  },
  {
    id: 'rb-009', title: 'Bulk outbound data transfer', severity: 'HIGH', mitre: 'T1048', action: 'isolate_host',
    description: 'Upload, curl -T or git archive piping data to an untrusted external IP',
    plain: 'A large amount of data is being sent out of the company to an unknown address.',
    entity: 'host', target: 'host',
    yaml: yaml({ title: 'Bulk outbound data transfer', id: 'rb-009', description: 'net_upload or curl/git-archive to an untrusted external IP', logsource: 'category: network_connection', selection: "action: net_upload OR CommandLine|contains: ['curl -T', 'git archive']", condition: 'selection and dst_ip|untrusted', level: 'high', tags: ['attack.exfiltration', 'attack.t1048'], fp: ['Approved offsite backups'] }),
    match: (e) => {
      const pattern = e.action === 'net_upload' || /curl\s.*-t\s|git archive/.test(msg(e));
      return pattern && isUntrustedIp(e.ip) ? [e] : null;
    },
  },
  {
    id: 'rb-010', title: 'Off-hours high-value payment transfer', severity: 'CRITICAL', mitre: 'T1657', action: 'disable_user',
    description: 'Transfer of 100,000 or more outside 07:00-20:00',
    plain: 'A very large payment was sent in the middle of the night.',
    entity: 'user', target: 'user',
    yaml: yaml({ title: 'Off-hours high-value payment transfer', id: 'rb-010', description: 'transfer amount >= 100000 outside 07-20 local time', logsource: 'category: payments', selection: 'action: transfer, amount|gte: 100000', condition: 'selection and (hour < 7 or hour > 20)', level: 'critical', tags: ['attack.impact', 'attack.t1657'], fp: ['Scheduled end-of-day settlement'] }),
    match: (e) => {
      if (e.action !== 'transfer') return null;
      const amount = Number(e.meta?.amount ?? 0);
      const hour = Number(e.meta?.hour ?? 12);
      return amount >= 100000 && (hour < 7 || hour > 20) ? [e] : null;
    },
  },
];

export const ruleById = (id: string) => RULES.find((r) => r.id === id);
export { within };
