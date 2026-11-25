import type { Action } from '../engine/types';

export const DISCLAIMER =
  'All scenarios and organizational profiles are educational simulations using reserved documentation IP ranges and invented accounts. Not affiliated with Meezan Bank, Salim Habib University, or Contour Software. No real data is used.';

export const CREDIT = 'Muhammad Nabil • F23CSC009 • Essentials of Cybersecurity';

export const ACTION_LABEL: Record<Action, string> = {
  isolate_host: 'Isolate host',
  block_ip: 'Block IP',
  disable_user: 'Disable user',
  reset_password: 'Reset password',
};

export const ACTION_PLAIN: Record<Action, string> = {
  isolate_host: 'quarantine this host: its network activity is blocked from now on',
  block_ip: 'put this address on the blocklist: all its traffic and sign-ins are dropped',
  disable_user: 'disable this account: every sign-in attempt is denied until released',
  reset_password: 'force a credential reset: sign-ins are challenged until the password is changed',
};

export const REAL_VS_SIM: { feature: string; real: string; sim: string }[] = [
  { feature: 'Detection pipeline', real: '10 Sigma-style rules with windows, thresholds, dedupe, correlation and incidents, running on every event', sim: 'None' },
  { feature: 'AI triage', real: 'Gemini via the server-side GEMINI_API_KEY proxy, with entity redaction; heuristic fallback is labelled', sim: 'None' },
  { feature: 'Threat intelligence', real: 'Live abuse.ch Feodo Tracker C2 IPs and OpenPhish phishing domains, refreshed hourly', sim: '7 extra indicators that match the simulated attacks' },
  { feature: 'Containment', real: 'Approved actions are enforced on all later telemetry (blocked, denied, quarantined, challenged) and on console sign-ins', sim: 'No external firewall, EDR or IdP is connected' },
  { feature: 'Authentication', real: 'Per-tier accounts with PBKDF2-SHA256 hashes, lockout after 5 failures, 8-hour sessions, real client IP and location', sim: 'Accounts live in this browser (no central identity provider)' },
  { feature: 'Riskbyte Platform telemetry', real: 'Real sign-ins, failed logins, sign-outs, client errors and connectivity from this console; brute-forcing the login really fires rb-001', sim: 'None' },
  { feature: 'Log ingestion', real: 'REST API with validation and 1000-event limit; upload real log files (auth.log/syslog, JSON, NDJSON)', sim: 'UDP syslog listener (browsers cannot open sockets)' },
  { feature: 'Organization telemetry', real: 'Anything you send or upload', sim: 'Baseline traffic and Demo attacks for Meezan, SHU, Contour and added orgs' },
  { feature: 'Audit ledger', real: 'SHA-256 hash chain, verification, tamper detection, rebuild, export, monitoring checkpoints and gap records', sim: 'None' },
  { feature: 'License', real: 'ECDSA P-256 signature verified with WebCrypto', sim: 'None' },
  { feature: 'Storage', real: 'localStorage, flushed on close, mirrored to Cache Storage; restored on reopen with the offline gap recorded', sim: 'Per-browser only (no shared server database)' },
];

export const LIMITATIONS = [
  'Monitoring runs while a browser has the console open; gaps are recorded in the ledger when it was closed. A production deployment would run the pipeline on a server.',
  'Data and accounts are stored per browser; another browser or device starts with its own copy.',
  'Containment is enforced inside Riskbyte (on telemetry and console sign-ins); it does not reconfigure external firewalls, EDR agents or identity providers.',
  'Organization telemetry (other than what you send or upload) is simulated, using documentation and private IP ranges.',
  'Detection is signature-based: only patterns written as rules are caught.',
  'Accuracy is checked by unit tests, not by a measured detection rate on labelled real-world data.',
  'Rule rb-002 flags the encoded-command pattern; it does not decode the payload.',
  'The UDP syslog listener is simulated: browsers cannot open network sockets.',
];
