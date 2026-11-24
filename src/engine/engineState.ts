import type { Alert, AuditBlock, AuditStatus, ClientId, EngineData, LogLevel, Origin, RiskEvent, Triage } from './types';
import { SEV_RANK } from './types';
import { appendBlock, genesis, verifyChain, tamper as tamperChain, repairChain, type AppendInput } from './audit';
import { MAX_BATCH, normalizeEvent, validateBatch } from './normalize';
import { detect, relatedEvents, alertEntity } from './detect';
import { matchIntel } from './intel';
import { attachToCase, refreshCaseStatus } from './cases';
import { triage, type TriageConfig } from './triage';
import { proposeContainment } from './containment';
import { clientName } from '../data/clients';

export const MAX_STORED_EVENTS = 2000;

export interface EngineDeps {
  log: (level: LogLevel, text: string) => void;
  triageConfig: () => TriageConfig;
  onChange: (data: EngineData, audit: AuditStatus) => void;
  /** test hook: override triage */
  triageFn?: (alert: Alert, events: RiskEvent[], cfg: TriageConfig, repeat: boolean) => Promise<Triage>;
}

export interface IngestOptions {
  origin: Origin;
  scenarioId?: string;
  actor: string;
}

export interface IngestOutcome {
  accepted: number;
  eventIds: string[];
  alertIds: string[];
  deduped: { ruleId: string; alertId: string; entity: string }[];
  processingMs: number;
}

export function emptyData(): EngineData {
  return { version: 1, events: [], alerts: [], cases: [], audit: [], counters: { event: 0, alert: 0, case: 0, totalIngested: 0, batches: 0, totalMs: 0 } };
}

const shortHash = (h: string) => h.slice(0, 6) + '...';

export class Engine {
  data: EngineData;
  auditStatus: AuditStatus = { intact: true, blocks: 0, checkedAt: new Date().toISOString() };
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private deps: EngineDeps, initial?: EngineData) {
    this.data = initial ?? emptyData();
  }

  /** Serializes all mutations so concurrent runs never interleave. */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private commit(next: EngineData) {
    this.data = next;
    this.deps.onChange(this.data, this.auditStatus);
  }

  async init(): Promise<void> {
    await this.exclusive(async () => {
      if (this.data.audit.length === 0) this.data = { ...this.data, audit: [await genesis()] };
      this.auditStatus = await verifyChain(this.data.audit);
      this.commit(this.data);
    });
  }

  async verify(): Promise<AuditStatus> {
    this.auditStatus = await verifyChain(this.data.audit);
    this.deps.onChange(this.data, this.auditStatus);
    return this.auditStatus;
  }

  private async append(input: AppendInput): Promise<AuditBlock> {
    const { chain, block } = await appendBlock(this.data.audit, input);
    this.data = { ...this.data, audit: chain };
    this.deps.log('OK', `audit block #${block.index} kind=${block.kind} hash=${shortHash(block.hash)} prev=${shortHash(block.prevHash)}`);
    return block;
  }

  /** The detection pipeline: validate → normalize → detect → dedupe → intel → case → audit, then triage. */
  async ingest(raw: unknown[], opts: IngestOptions): Promise<IngestOutcome> {
    const v = validateBatch(raw);
    if (!v.ok) throw Object.assign(new Error('validation'), { problems: v.problems });
    if (raw.length > MAX_BATCH) throw Object.assign(new Error('too large'), { tooLarge: raw.length });

    const stage = await this.exclusive(async () => {
      const t0 = performance.now();
      let { counters } = this.data;
      const newEvents: RiskEvent[] = raw.map((r, i) => normalizeEvent(r as Record<string, unknown>, counters.event + i + 1, opts.origin));
      counters = { ...counters, event: counters.event + newEvents.length, totalIngested: counters.totalIngested + newEvents.length };
      let events = [...this.data.events, ...newEvents];
      if (events.length > MAX_STORED_EVENTS) events = events.slice(events.length - MAX_STORED_EVENTS);
      for (const e of newEvents) {
        this.deps.log('INFO', `normalize event ${e.id} host=${e.host ?? '-'} user=${e.user ?? '-'}${e.ip ? ` ip=${e.ip}` : ''} action=${e.action}`);
      }

      const { fired, deduped } = detect(newEvents, events, this.data.alerts);
      for (const d of deduped) this.deps.log('INFO', `dedupe ${d.rule.id} entity=${d.entity} within 60s → linked to ${d.alertId}`);

      let alerts = [...this.data.alerts];
      let cases = [...this.data.cases];
      const created: Alert[] = [];
      for (const d of fired) {
        counters = { ...counters, alert: counters.alert + 1 };
        const id = `A-${String(counters.alert).padStart(4, '0')}`;
        const related = relatedEvents(d, events);
        const intelHits = matchIntel(related);
        const proposed = proposeContainment(d.rule, d.event);
        const caseRes = attachToCase(cases, { client: d.event.client, entity: d.entity, entityType: d.rule.entity, severity: d.rule.severity, alertId: id, ts: d.event.ts }, counters.case + 1);
        if (caseRes.created) counters = { ...counters, case: counters.case + 1 };
        cases = caseRes.cases;
        const alert: Alert = {
          id, ruleId: d.rule.id, client: d.event.client, severity: d.rule.severity, title: d.rule.title, ts: d.event.ts,
          host: d.event.host, user: d.event.user, ip: d.event.ip, status: 'new', caseId: caseRes.caseId,
          eventIds: related.map((e) => e.id), intelHits, proposed, scenarioId: opts.scenarioId,
        };
        alerts.push(alert);
        created.push(alert);
        this.deps.log('ALERT', `rule ${d.rule.id} fired severity=${d.rule.severity} client=${clientName(d.event.client)} entity=${d.entity}`);
        if (intelHits.length === 0) this.deps.log('INFO', `intel no match for ${id}`);
        for (const h of intelHits) this.deps.log('INFO', `intel match ${h.value} (${h.category}, confidence ${h.confidence.toFixed(2)})`);
        this.deps.log('INFO', `case ${caseRes.created ? 'opened' : 'updated'} ${caseRes.caseId} entity=${d.entity}`);
      }

      // Late correlation: new events that touch an open alert's host/user are attached as evidence.
      const createdIds = new Set(created.map((a) => a.id));
      alerts = alerts.map((a) => {
        if (createdIds.has(a.id) || a.status === 'executed' || a.status === 'dismissed') return a;
        const add = newEvents.filter((e) => e.client === a.client && Math.abs(Date.parse(e.ts) - Date.parse(a.ts)) <= 600_000 &&
          ((a.host && e.host === a.host) || (a.user && e.user === a.user)) && !a.eventIds.includes(e.id));
        if (!add.length) return a;
        const merged = new Map(a.intelHits.map((h) => [h.value, h]));
        for (const h of matchIntel(add)) merged.set(h.value, h);
        this.deps.log('INFO', `correlated ${add.map((e) => e.id).join(',')} → ${a.id}`);
        return { ...a, eventIds: [...a.eventIds, ...add.map((e) => e.id)], intelHits: [...merged.values()] };
      });

      const processingMs = Math.max(0.1, Math.round((performance.now() - t0) * 10) / 10);
      counters = { ...counters, batches: counters.batches + 1, totalMs: counters.totalMs + processingMs };
      this.data = { ...this.data, events, alerts, cases, counters };

      const batchClient: ClientId = newEvents[0].client;
      await this.append({ client: batchClient, actor: opts.actor, kind: 'ingest.accepted', detail: `${newEvents.length} event(s) accepted via ${opts.origin} (${newEvents[0].id}..${newEvents[newEvents.length - 1].id})` });
      for (const a of created) {
        await this.append({ client: a.client, actor: 'system:detector', kind: 'alert.created', alertId: a.id, detail: `${a.ruleId} ${a.title} severity=${a.severity} entity=${alertEntity(a)} case=${a.caseId}` });
      }
      this.auditStatus = await verifyChain(this.data.audit);
      this.commit(this.data);
      return {
        newEvents, created,
        outcome: {
          accepted: newEvents.length,
          eventIds: newEvents.map((e) => e.id),
          alertIds: created.map((a) => a.id),
          deduped: deduped.map((d) => ({ ruleId: d.rule.id, alertId: d.alertId, entity: d.entity })),
          processingMs,
        } as IngestOutcome,
      };
    });

    // Triage outside the lock (Gemini can take seconds) so the UI never blocks.
    await Promise.all(stage.created.map((a) => this.runTriage(a.id)));
    return stage.outcome;
  }

  private async runTriage(alertId: string) {
    const alert = this.data.alerts.find((a) => a.id === alertId);
    if (!alert) return;
    const evs = this.data.events.filter((e) => alert.eventIds.includes(e.id));
    const repeat = this.data.alerts.some((a) => a.id !== alert.id && a.client === alert.client && alertEntity(a) === alertEntity(alert) && Date.parse(a.ts) <= Date.parse(alert.ts));
    const cfg = this.deps.triageConfig();
    if (cfg.apiKey) this.deps.log('INFO', `triage ${alert.id} sending redacted evidence to gemini (${cfg.model})`);
    const result = await (this.deps.triageFn ?? triage)(alert, evs, cfg, repeat);
    if (result.fallbackReason) this.deps.log('WARN', `gemini unavailable (${result.fallbackReason}); falling back to heuristic`);
    this.deps.log('INFO', `triage provider=${result.provider} verdict=${result.verdict} confidence=${result.confidence} ${result.ms}ms`);
    await this.exclusive(async () => {
      const current = this.data.alerts.find((a) => a.id === alertId);
      if (!current) return; // reset while triaging
      const status = current.status === 'new' ? 'triaged' : current.status;
      this.data = { ...this.data, alerts: this.data.alerts.map((a) => (a.id === alertId ? { ...a, triage: result, status } : a)) };
      this.deps.log('INFO', `proposed action ${current.proposed.action} ${current.proposed.target} (awaiting approval)`);
      await this.append({ client: current.client, actor: `ai:${result.provider}`, kind: 'triage.completed', alertId, detail: `verdict=${result.verdict} confidence=${result.confidence} provider=${result.provider}${result.provider === 'gemini' ? ` model=${result.model}` : ''}` });
      this.auditStatus = await verifyChain(this.data.audit);
      this.commit(this.data);
    });
  }

  async decide(alertId: string, kind: 'approve' | 'dismiss', actor: string): Promise<{ status: number; body: Record<string, unknown> }> {
    return this.exclusive(async () => {
      const a = this.data.alerts.find((x) => x.id === alertId);
      if (!a) return { status: 404, body: { error: 'alert not found', alertId } };
      if (a.outcome) {
        const same = (a.outcome.kind === 'approved') === (kind === 'approve');
        if (same) return { status: 200, body: { ok: true, idempotent: true, alert: a } };
        return { status: 409, body: { error: 'conflict', detail: `Alert ${a.id} was already ${a.outcome.kind} by ${a.outcome.by}; it cannot be ${kind === 'approve' ? 'approved' : 'dismissed'} now.` } };
      }
      const at = new Date().toISOString();
      if (kind === 'approve') this.deps.log('INFO', `dry-run: would execute ${a.proposed.action} ${a.proposed.target}`);
      const block = await this.append({
        client: a.client,
        actor,
        kind: kind === 'approve' ? 'containment.approved' : 'alert.dismissed',
        alertId: a.id,
        detail: kind === 'approve' ? `dry-run ${a.proposed.action} ${a.proposed.target} (no device touched)` : `alert dismissed; no action taken on ${a.proposed.target}`,
      });
      const updated: Alert = {
        ...a,
        status: kind === 'approve' ? 'executed' : 'dismissed',
        outcome: { by: actor, at, blockIndex: block.index, hash: block.hash, kind: kind === 'approve' ? 'approved' : 'dismissed' },
      };
      const alerts = this.data.alerts.map((x) => (x.id === a.id ? updated : x));
      const cases = refreshCaseStatus(this.data.cases, (id) => alerts.find((x) => x.id === id)?.status);
      this.data = { ...this.data, alerts, cases };
      this.auditStatus = await verifyChain(this.data.audit);
      this.commit(this.data);
      return { status: 200, body: { ok: true, alert: updated, block } };
    });
  }

  async reset(actor: string) {
    return this.exclusive(async () => {
      const g = await genesis();
      const { chain } = await appendBlock([g], { client: 'system', actor, kind: 'system.reset', detail: 'Demo data reset: events, alerts, cases and ledger cleared' });
      this.data = { ...emptyData(), audit: chain };
      this.auditStatus = await verifyChain(chain);
      this.deps.log('WARN', `demo data reset by ${actor}; new ledger genesis hash=${shortHash(g.hash)}`);
      this.commit(this.data);
    });
  }

  async tamper(): Promise<number> {
    return this.exclusive(async () => {
      const { chain, index } = tamperChain(this.data.audit);
      this.data = { ...this.data, audit: chain };
      this.deps.log('WARN', `block #${index} detail edited in storage without rehashing (tamper simulation)`);
      this.auditStatus = await verifyChain(chain);
      if (!this.auditStatus.intact) this.deps.log('ERROR', `audit verification FAILED: chain broken at block #${this.auditStatus.brokenAt}`);
      this.commit(this.data);
      return index;
    });
  }

  async repair(actor: string): Promise<number> {
    return this.exclusive(async () => {
      const { chain, from } = await repairChain(this.data.audit, actor);
      this.data = { ...this.data, audit: chain };
      this.auditStatus = await verifyChain(chain);
      this.deps.log('OK', `ledger rebuilt from block #${from}; ledger.repaired appended; chain ${this.auditStatus.intact ? 'intact' : 'still broken'}`);
      this.commit(this.data);
      return from;
    });
  }

  stats() {
    const d = this.data;
    return {
      events: d.events.length,
      totalIngested: d.counters.totalIngested,
      alerts: d.alerts.length,
      openAlerts: d.alerts.filter((a) => a.status === 'new' || a.status === 'triaged').length,
      cases: d.cases.length,
      openCases: d.cases.filter((c) => c.status === 'open').length,
      critical: d.alerts.filter((a) => SEV_RANK[a.severity] === 3).length,
      batches: d.counters.batches,
      avgMs: d.counters.batches ? Math.round((d.counters.totalMs / d.counters.batches) * 10) / 10 : 0,
      auditBlocks: d.audit.length,
      auditIntact: this.auditStatus.intact,
      brokenAt: this.auditStatus.brokenAt,
    };
  }
}
