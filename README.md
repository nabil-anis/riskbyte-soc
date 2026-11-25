# Riskbyte · mini SOC platform

**Muhammad Nabil • F23CSC009 • Essentials of Cybersecurity**

> All scenarios and organizational profiles are educational simulations using reserved documentation IP ranges and invented accounts. Not affiliated with Meezan Bank, Salim Habib University, or Contour Software. No real data is used.

Riskbyte is a mini Security Operations Center (SOC) that runs entirely in the browser. It ingests security logs, detects threats with 10 Sigma-style rules, cross-references threat intelligence, triages each alert with AI (Google Gemini, with a local heuristic fallback), proposes a containment action that **waits for human approval**, and records every action in a **SHA-256 hash-chained audit ledger** that exposes tampering. Alerts on the same host or user are grouped into Cases.

## Product structure

The landing page has four cards. Each tier is its own console with its own navigation:

| Workspace | Who | Pages |
|---|---|---|
| **Security Analyst** (Tier 1) | SOC analyst, the human in the loop | Overview (approval queue, KPIs, agent activity) · Alert queue (agent timeline, AI assessment, evidence, approve/dismiss) · Incidents · Agent activity log |
| **Administrator** (Tier 2) | Platform owner | Overview · Organizations (onboard/offboard) · AI agent & policy (Gemini key, model, per-action approval vs auto-execute, confidence threshold) · Detection rules (Sigma YAML) · Threat intel · Audit ledger (verify, rebuild, export) · System (license, storage, API matrix, data reset) |
| **Telemetry Ingestion** (Tier 3) | Log pipeline operator | Sources (endpoints, collectors per org, throughput) · Live stream · Send events (REST API) · Pipeline console |
| **Demo** | Attack simulator | Pick one of 11 attacks → choose the organization → launch. Optional continuous mode. Then open the analyst or telemetry console to see what the agent did. |

### What the AI agent does for every detection

1. **Detect**: a Sigma-style rule matches the incoming telemetry.
2. **Correlate**: pulls related events on the same host/user (and attaches events that arrive later).
3. **Enrich**: checks IPs and domains against threat intel.
4. **Incident**: opens or links an incident for that entity.
5. **Triage**: asks Gemini (redacted evidence) or the local heuristic model for a verdict, confidence and investigation steps.
6. **Recommend**: proposes a containment action.
7. **Gate**: by default waits for analyst approval. If the administrator set that action to *Auto* and the verdict is MALICIOUS above the threshold, the agent executes it itself (as `ai:riskbyte-agent`).
8. **Record**: every step that changes state goes into the SHA-256 hash-chained audit ledger.

Each alert shows this as a timeline ("What the agent did"), and the analyst overview shows the live agent activity feed.

## Run locally (Windows PowerShell)

```powershell
npm install
```

```powershell
npm run dev
```

Open the URL Vite prints (usually http://localhost:5173).

Other scripts: `npm test` (Vitest, 63 tests), `npm run build` (type-check + production build into `dist/`), `npm run preview` (serve the build).

## Deploy to Vercel

1. Go to vercel.com → **Add New… → Project** → **Import** the `riskbyte` GitHub repository.
2. Framework preset: **Vite** (detected from `vercel.json`). Build command `npm run build`, output directory `dist`.
3. Optional: add `GEMINI_API_KEY` under Environment Variables for Gemini-powered triage. Without it, the agent uses the local heuristic model.
4. Click **Deploy** and open the generated link. It lands on the workspace picker. Refreshing any page (`#analyst/alerts`, `#admin/orgs`, …) works because the location lives in the URL hash and `vercel.json` rewrites every path to `index.html`.

## Gemini API key

**Recommended: server-side key.** In Vercel → Project → Settings → Environment Variables, add `GEMINI_API_KEY` (all environments) and redeploy. The agent then calls Gemini through the serverless function `api/gemini.ts`, which adds the key on the server. The key is never sent to browsers, and the endpoint only accepts the app's fixed triage and ping request shapes. Locally, put `GEMINI_API_KEY=...` in `.env.local` (gitignored); the Vite dev server serves the same `/api/gemini` route.

Check it in **Administrator → AI agent & policy**: it shows *Server key (GEMINI_API_KEY): configured ✓*, and **Test connection** pings Gemini through the server. Every triaged alert shows `gemini · <model>`, or `heuristic (Gemini unavailable: <reason>)` if a call fails (timeout 12 s, rate limit, etc.).

Optional: a browser-side key can be pasted on the same page as an override (stored in localStorage). `VITE_GEMINI_API_KEY` is also supported but is **public** inside the built bundle, so prefer `GEMINI_API_KEY`.

Before evidence leaves the browser, IPs, usernames, hostnames and the organization name are replaced with tokens like `[REDACTED_IP_1]` and mapped back locally.

## 24/7 monitoring, escalation and logs

- **Continuous detection**: while the app is open, baseline telemetry from every organization (logins, DNS, processes, VPN sessions, routine payments) flows into the pipeline every few seconds and is scanned against all 10 rules. Each scan writes one log line. Every 5 minutes a `monitoring.checkpoint` block goes into the audit ledger.
- **Tiers wake up only when something is wrong**: the landing page shows *All clear* or *Attention required*. Each tier card shows **STANDBY** or **ACTIVE**, with the reason:
  - Tier 1 Security Analyst: alerts awaiting approval.
  - Tier 2 Administrator: an open critical incident, or a ledger integrity failure.
  - Tier 3 Telemetry Ingestion: hostile telemetry detected in the last 5 minutes, or malformed batches rejected.
- **Live logs** (Telemetry Ingestion → Live logs): a SIEM-style viewer of every user action (clicks, navigation, filters, approvals, launches, settings changes; key values are never logged), API calls, pipeline scans, agent steps and ledger writes. It filters by source, level and text, can pause, and exports a `.log` file. The last 800 lines survive reloads.

## What is real and what is simulated

| Area | Real | Simulated |
|---|---|---|
| Detection pipeline | 10 Sigma-style rules with windows, thresholds, dedupe, correlation and incidents on every event | None |
| AI triage | Gemini via the server-side `GEMINI_API_KEY` proxy, with entity redaction; heuristic fallback is labelled | None |
| Threat intelligence | Live abuse.ch Feodo Tracker C2 IPs and OpenPhish phishing domains (via `/api/intel`), refreshed hourly | 7 extra indicators that match the simulated attacks |
| Containment | Approved actions are **enforced**: blocklisted IPs are dropped, disabled accounts denied, isolated hosts lose network events, reset accounts are challenged; also applies to console sign-ins; released from Administrator → Containment | No external firewall, EDR or IdP is connected |
| Authentication | Per-tier accounts, PBKDF2-SHA256 (150k iterations), lockout after 5 failures, 8-hour sessions, real client IP and location (`/api/whoami`) | Accounts are per browser (no central IdP) |
| Riskbyte Platform telemetry | Real sign-ins, failed logins, sign-outs, client errors, connectivity. Brute-forcing the login really fires rb-001 | None |
| Log ingestion | REST API with validation and 1000-event limit; **upload real log files** (auth.log/syslog, JSON, NDJSON) | UDP syslog listener (browsers cannot open sockets) |
| Organization telemetry | Anything you send or upload | Baseline traffic and Demo attacks for Meezan, SHU, Contour and added orgs |
| Audit ledger | SHA-256 hash chain, verification, tamper detection, rebuild, export, monitoring checkpoints and gap records | None |
| License | ECDSA P-256 signature verified with WebCrypto (signing key discarded) | None |
| Storage | localStorage, flushed when the tab closes, mirrored to Cache Storage, app shell cached by a service worker; restored on reopen with the offline gap recorded | Per browser only (no shared server database) |

## Limitations

1. Monitoring runs while a browser has the console open; when it was closed, a `monitoring.gap` block records it. A production deployment would run the pipeline on a server.
2. Data and accounts are stored per browser; another browser or device starts with its own copy.
3. Containment is enforced inside Riskbyte (on telemetry and console sign-ins); it does not reconfigure external firewalls, EDR agents or identity providers.
4. Organization telemetry, apart from what you send or upload, is simulated using documentation and private IP ranges.
5. Detection is signature-based: only patterns written as rules are caught.
6. Accuracy is checked by unit tests, not by a measured detection rate on labelled real-world data.
7. Rule rb-002 flags the encoded-command pattern; it does not decode the payload.
8. The UDP syslog listener is simulated: browsers cannot open network sockets.

## Sign-in and recovery

The first time you open a tier, you create its account (username + password). Passwords are hashed with PBKDF2 in the browser and never stored in plain text. Five wrong passwords lock the account for 60 seconds, and the failures are real telemetry for the *Riskbyte Platform* organization, so they can trigger the brute-force rule. If a containment blocklists your own IP, only the Administrator can still sign in (break-glass, audited) and release it under **Administrator → Containment**. Forgotten password: use *Can't sign in? Delete this account* on the sign-in dialog (audited) and create a new one.

## Assumptions

- **Event timestamps** for scenarios start at "now" and are spaced by the offsets in the spec (brute force: 4 s apart, so 6 attempts fit in 20 s).
- **"Untrusted IP"** means any address outside the private ranges (10/8, 172.16/12, 192.168/16, 127/8). That makes `203.0.113.77` untrusted for rb-006 even though it is not in threat intel, as the spec requires.
- **rb-008 baseline geography**: a VPN login counts as anomalous when `meta.geo` starts with "Foreign", or, when no geo is given, when the IP is a known indicator.
- **rb-007 bulk rename** threshold is 500 files in one `file_rename_bulk` event.
- **Dedupe**: the same rule for the same client + entity within 60 s does not open a second alert. Running the same scenario twice quickly links the new events to the existing alert, and the Demo panel says so.
- **Correlated telemetry / intel** for an alert = the triggering events plus events within 10 minutes on the same host or user (same IP for brute-force rules). Events that arrive later for an open alert are attached too, so the ransomware DNS lookup to `ransomware-c2.net` lands on the shadow-copy alert.
- **Cases** close automatically once every alert in them is approved or dismissed.
- **Phishing simulation for orgs without a spoofed domain** (Contour and any org you add) reuses `shu-admissions-phish.com`, since the indicator list has only two phishing domains.
- **Engine is always on**: like a real SOC platform, the pipeline and agent run continuously while the site is open. A static site cannot run when no browser has it open; a production deployment would run the pipeline on a server.
- **Baseline telemetry** is generated (documentation and private IP ranges) to show continuous monitoring; it is designed not to match any rule.
- **Organizations** are stored with the platform data. Offboarding keeps history but rejects new telemetry for that org.
- **Audit log tampering** is one of the simulator's attacks (an insider editing a stored record); admins detect and rebuild it from the Audit ledger page.
- **Processing time** shown in the UI and `stats` is the measured detection pipeline per batch (normalize → detect → intel → case → audit), not including AI triage. AI latency is shown separately on each triage card.
- **Actors** in the audit ledger are `analyst:soc.analyst`, `admin:soc.admin`, `ingest:ingest.agent`, plus `system:detector` and `ai:<provider>` for automated steps.
- The heuristic uses the fixed scenario confidences only when the alert came from that scenario's run **and** fired that scenario's rule.

## Tech stack

Vite 5, React 18, TypeScript (strict), Zustand, plain CSS with design tokens (`src/styles/tokens.css`), Vitest. No backend, no serverless functions, no database. Fonts: Source Serif 4, Inter, JetBrains Mono (Google Fonts with system fallbacks).

```
src/
  engine/   types, normalize, detect, intel, cases, triage, gemini, redact,
            heuristic, audit, sha256 (WebCrypto + pure-TS fallback), containment,
            api (12-route mock REST API), auth, generators, engineState, license
  data/     clients, scenarios (12), rules (10 + YAML), indicators (7), copy
  store/    Zustand store + localStorage persistence
  components/ pages/ styles/ tests/
docs/PRESENTATION_NOTES.md
```

Presentation notes, checklist, spoken script and professor Q&A: [docs/PRESENTATION_NOTES.md](docs/PRESENTATION_NOTES.md).
