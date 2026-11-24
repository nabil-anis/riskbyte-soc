export type Role = 'ingest' | 'analyst' | 'admin';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Verdict = 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
/** Organization id (slug). Built-in: meezan, shu, contour; admins can add more. */
export type ClientId = string;
export type Action = 'isolate_host' | 'block_ip' | 'disable_user' | 'reset_password';
export type EventSource = 'syslog' | 'vpn' | 'proxy' | 'endpoint' | 'web' | 'gateway' | 'git' | 'payments';
export type Origin = 'demo' | 'playground' | 'dispatcher' | 'ingest-api';

export interface RiskEvent {
  id: string;
  ts: string;
  client: ClientId;
  source: EventSource;
  host?: string;
  user?: string;
  ip?: string;
  domain?: string;
  process?: string;
  action: string;
  message: string;
  meta?: Record<string, string | number | boolean>;
  origin: Origin;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  mitre: string;
  action: Action;
  description: string;
  plain: string;
  yaml: string;
  /** Returns the triggering events when the rule fires for `e`, else null. */
  match: (e: RiskEvent, window: RiskEvent[]) => RiskEvent[] | null;
  windowSec?: number;
  threshold?: number;
  groupBy?: 'ip' | 'user' | 'host';
  /** Which entity the alert/case is keyed on. */
  entity: 'ip' | 'user' | 'host';
  /** What the containment action targets. */
  target: 'ip' | 'user' | 'host';
}

export interface Triage {
  provider: 'gemini' | 'heuristic';
  model: string;
  verdict: Verdict;
  confidence: number;
  summary: string;
  steps: string[];
  redacted: boolean;
  redactionCounts?: Record<string, number>;
  fallbackReason?: string;
  ms: number;
}

export interface Indicator {
  value: string;
  type: 'ip' | 'domain';
  category: string;
  confidence: number;
  note: string;
}

export interface Alert {
  id: string;
  ruleId: string;
  client: ClientId;
  severity: Severity;
  title: string;
  ts: string;
  host?: string;
  user?: string;
  ip?: string;
  status: 'new' | 'triaged' | 'executed' | 'dismissed';
  caseId: string;
  eventIds: string[];
  intelHits: Indicator[];
  triage?: Triage;
  proposed: { action: Action; target: string };
  scenarioId?: string;
  outcome?: { by: string; at: string; blockIndex: number; hash: string; kind: 'approved' | 'dismissed'; auto?: boolean };
  /** What the AI agent did for this alert, in order. */
  timeline: AgentStep[];
}

export type AgentStepKind = 'detect' | 'correlate' | 'enrich' | 'case' | 'triage' | 'propose' | 'await' | 'execute' | 'dismiss' | 'auto';
export interface AgentStep {
  ts: string;
  kind: AgentStepKind;
  text: string;
}

export interface Org {
  id: ClientId;
  name: string;
  sector: string;
  description?: string;
  createdAt: string;
  builtIn?: boolean;
}

export type ApprovalMode = 'approve' | 'auto';
export interface AgentPolicy {
  modes: Record<Action, ApprovalMode>;
  /** auto-execute only when verdict is MALICIOUS and confidence >= this */
  minConfidence: number;
}

export interface Case {
  id: string;
  client: ClientId;
  entity: string;
  entityType: 'host' | 'user' | 'ip';
  severity: Severity;
  status: 'open' | 'closed';
  openedAt: string;
  alertIds: string[];
}

export interface AuditBlock {
  index: number;
  ts: string;
  client: ClientId | 'system';
  actor: string;
  kind: string;
  alertId?: string;
  detail: string;
  prevHash: string;
  hash: string;
}

export interface AuditStatus {
  intact: boolean;
  brokenAt?: number;
  blocks: number;
  checkedAt: string;
}

export type LogLevel = 'INFO' | 'WARN' | 'ALERT' | 'ERROR' | 'OK';
export interface LogLine {
  id: number;
  ts: string;
  level: LogLevel;
  text: string;
}

export interface EngineData {
  version: 2;
  orgs: Org[];
  events: RiskEvent[];
  alerts: Alert[];
  cases: Case[];
  audit: AuditBlock[];
  counters: { event: number; alert: number; case: number; totalIngested: number; batches: number; totalMs: number };
}

export const SEV_RANK: Record<Severity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
export const maxSeverity = (a: Severity, b: Severity): Severity => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);
