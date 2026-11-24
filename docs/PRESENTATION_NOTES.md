# Riskbyte · Presentation Notes

**Muhammad Nabil • F23CSC009 • Essentials of Cybersecurity**

Before you start: check the AI engine. Open Settings (gear). If a Gemini key is saved, the triage card will say `gemini · gemini-2.5-flash`. If not, it says `heuristic`. Say which one is running before the demo, and never imply Gemini produced a heuristic verdict.

Tip: as Administrator, press **Reset Demo Data** on the Demo page right before presenting so the ledger starts clean.

## Checklist

- [ ] Open the Vercel link.
- [ ] Click **Security Analyst Dashboard**.
- [ ] Turn the **Engine** on and let the terminal boot.
- [ ] Open the **Demo** tab.
- [ ] Show the **Client Selector** (Meezan Bank, Salim Habib University, Contour Software).
- [ ] Select **Meezan Bank** and point out the profile card (what they do, risks).
- [ ] Click **Run Attack** on **Fake Bank Login Phishing**.
- [ ] Walk through the 7 steps, reading the "What this means" and "Why this matters" lines.
- [ ] Click **Approve & Execute Action** at step 6; point out step 7 and the SHA-256 block hash.
- [ ] Point out the **What Happened?** box.
- [ ] Open **Audit Trail** and show `Hash Chain: Intact (SHA-256)`.
- [ ] (Wow moment) In **Admin Overview** click **Simulate tampering**, show the badge turn red, then **Repair**. (Switch to Administrator from the role badge first; the analyst cannot tamper.)
- [ ] Show the 10 Sigma rules and the platform metrics in **Admin Overview**.
- [ ] Close with the credit: *Muhammad Nabil • F23CSC009 • Essentials of Cybersecurity*.

## Spoken script (one paragraph per step)

**Open & sign in.** "This is Riskbyte, a mini Security Operations Center. Think of it as a security guard for a company's computers. I'll sign in as a security analyst, the person who decides what to do about threats."

**Engine on.** "I turn the engine on. The terminal at the bottom is the engine's live log: it loads ten detection rules, seven known-bad indicators, verifies the audit ledger, and tells us which AI is doing triage. Everything runs live in the browser."

**Demo tab & client selector.** "Riskbyte serves three simulated organisations: a bank, a university and a software company. Each has different assets and risks. I'll pick Meezan Bank: mobile and internet banking, SMS, and instant Raast payments, so phishing and account takeover are the big risks."

**Run Attack.** "I launch a simulated phishing attack: a fake bank SMS leads a customer to a look-alike login page, and the attacker then logs in with the stolen password."

**Step 1 · Attack launched.** "Here is what the attacker did. All addresses are reserved documentation IPs, so nothing real is touched."

**Step 2 · Event received & normalized.** "Riskbyte received two log events through its ingest API and converted them into one common format. You can see the measured processing time in milliseconds."

**Step 3 · Detection rule.** "Rule rb-006 fired: a click on a flagged phishing link followed by a login from an untrusted address within ten minutes. It's a Sigma-style rule mapped to MITRE ATT&CK T1566.002."

**Step 4 · Threat intel.** "Both the domain and the proxy IP are on our known-bad list. That turns a suspicion into evidence."

**Step 5 · AI triage.** "The AI reads the evidence and returns a verdict, a confidence score and investigation steps. Before anything goes to Gemini, names, hosts and IPs are replaced by tokens, so confidential data never leaves. The badge shows exactly which engine produced this."

**Step 6 · Approval gate.** "Riskbyte proposes resetting the customer's password, but it does nothing on its own. A wrong automatic action could lock out real customers, so a human approves. I click Approve & Execute. It's a dry run: no real system changes."

**Step 7 · Audit record.** "My approval is now block number N in a hash-chained ledger. Each block's SHA-256 hash includes the previous block's hash, so editing any old entry breaks the chain."

**What Happened?** "Here's the plain-English summary of the whole incident, which a manager could read without any jargon."

**Audit Trail.** "Every action is listed here with its hash, and the badge says Hash Chain: Intact."

**Tamper demo.** "Now let me play an intruder who edits the log to hide their tracks. I switch to Administrator and click Simulate tampering. Instantly the chain breaks at that block and every badge turns red. Repair rebuilds the chain and records that a repair happened. This is tamper-evident, not tamper-proof."

**Rules & metrics.** "These are the ten detection rules; clicking one shows its Sigma YAML. Up top: total telemetry, open incidents, which AI is active, ledger status and average processing time."

**Close.** "The attacker is simulated, but the detection, AI triage, approval gate and audit chain are real code running live. Muhammad Nabil, F23CSC009, Essentials of Cybersecurity. Thank you."

## Real vs Simulated

| Feature | REAL in this build | SIMULATED |
|---|---|---|
| Ingestion pipeline | Real in-browser API layer, validation, normalization, 1000-event limit | Telemetry is generated by scenarios (documentation IPs); UDP syslog is simulated |
| Detection engine | Real Sigma-style rules with sliding windows and thresholds, unit-tested | None |
| Threat intelligence | Real indicator lookup | Indicators are documentation/placeholder values |
| AI triage | Real Gemini API call when a key is set; real entity redaction | Heuristic engine is used when there is no key or the call fails |
| Audit ledger | Real SHA-256 hash chain and verification | None |
| Containment | Real approval flow, state change and audit record | Execution is dry-run; no device or firewall is touched |
| Engine / "server" | Real in-browser engine with real logs | It is not an OS process; the toggle controls the in-browser engine |
| License | Real JSON structure and checks | Signature is a demonstration value |

## Honest limitations

1. Containment is dry-run only. Approving `isolate_host` records the decision and audit block but does not touch any real device, Wi-Fi adapter or firewall.
2. Data lives in the browser (localStorage). Clearing site data or using another browser starts fresh.
3. The Engine is an in-browser engine, not an operating-system process or a real UDP socket. A website cannot open UDP ports.
4. No Active Directory/LDAP sync; users such as `customer.tariq` come from telemetry.
5. The license is a demonstration value.
6. The Gemini key is stored in the browser for a class project. For production it would live on a server.
7. Attack events are generated simulations using documentation IP ranges.
8. Detection is signature-based: only patterns written as rules are caught; new techniques can slip through.
9. Accuracy is checked by unit tests (functional), not by a measured detection rate on real data.
10. Rule rb-002 flags the encoded-command pattern; it does not decode the payload.
11. Authentication is simulated (dev tokens); production would need real authentication.

## Professor Q&A

1. **What format do rules follow?** Sigma-style YAML: detection condition, severity, MITRE ATT&CK ID, sliding time window. Shareable across SIEMs.
2. **What if someone tampers with the audit log?** Each block's SHA-256 depends on the previous block. Editing a row breaks the chain and the dashboard turns red with `TAMPERED` and the block number (show the live demo). It is tamper-evident, not tamper-proof: someone with full write access could recompute the whole chain, so in production the latest hash would also be stored somewhere separate. It's a hash-chained ledger, like a blockchain's block linking, but not a blockchain (no consensus, no distribution).
3. **Why a human approval gate?** Fully automated containment can cause outages, like isolating a critical server or freezing legitimate payments. The AI proposes, a human approves.
4. **How does triage avoid leaking confidential data?** A redaction layer replaces IPs, users, hosts and the organisation name with tokens like `[REDACTED_IP_1]` before anything is sent, and maps them back locally.
5. **Alert vs Case?** An alert is one rule detection. A case groups alerts for the same host or user so the analyst handles one incident.
6. **What if Gemini is down or there is no internet?** The engine falls back to a local heuristic triage and the badge shows which engine produced the result.
7. **How are clients separated?** Every event, alert, case and audit block carries a client field; the UI shows client badges and filters.
8. **Can an ingest account approve actions?** No. The ingest role can only send telemetry; approve and dismiss return 403 Forbidden.
9. **Why documentation IPs?** RFC 5737 reserves 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 for documentation, so simulations never touch real hosts. (1.2.3.4 is a common placeholder, used here as a stand-in.)
10. **How fast would it detect ransomware?** Detection runs as soon as events are ingested; the app measures and shows the real processing time in milliseconds. Don't quote a fixed number.
11. **What does it NOT detect?** Rules are signature-based, so a brand-new technique that matches no rule slips through.
12. **How do you know the triage is accurate?** Unit tests cover every rule and scenario: a functional check, not a measured detection rate. No large labelled evaluation has been run.
13. **What about authentication?** Simulated role tokens (`dev-ingest`, `dev-analyst`, `dev-admin`). Production would use real authentication and server-side checks.
14. **Which AI produced the verdict?** Check the engine badge on the triage card. If it says `heuristic`, don't imply Gemini produced it.
15. **Is this just a demo?** The attacks are simulated for safety, but detection, AI decision, approval and logging are real code running live in the browser. Only the attacker is made up. Plain English: Riskbyte reads the computers' diaries, checks them against rules and a known-bad list, an AI gives a verdict, a human must press Approve, and every decision goes into a log that shows if anyone changes it later.

**Wording to avoid:** no unsourced statistics (say "a large share of analyst time"); never say the app "decoded" the PowerShell (it flags obfuscation indicators); never say "blockchain".
