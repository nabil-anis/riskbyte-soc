import type { Verdict } from './types';

export const SYSTEM_INSTRUCTION =
  'You are a SOC triage assistant. Given one redacted security alert and its evidence, return a verdict (MALICIOUS, SUSPICIOUS or BENIGN), a confidence 0-100, a plain-English summary of at most 3 sentences, and 3 to 5 numbered investigation steps. Use only the evidence provided. Entity tokens like [REDACTED_IP_1] are placeholders; keep them as written. Never invent indicators. You only propose; a human approves any action.';

export const DEFAULT_MODEL = 'gemini-2.5-flash';
export const TIMEOUT_MS = 12_000;

export interface GeminiResult {
  verdict: Verdict;
  confidence: number;
  summary: string;
  steps: string[];
}

export class GeminiError extends Error {
  constructor(public short: string, message: string) {
    super(message);
  }
}

const VERDICTS: Verdict[] = ['MALICIOUS', 'SUSPICIOUS', 'BENIGN'];

export function parseGeminiResponse(json: unknown): GeminiResult {
  const text = (json as { candidates?: { content?: { parts?: { text?: string }[] } }[] })?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new GeminiError('empty response', 'Gemini returned no candidate text');
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new GeminiError('malformed JSON', 'Gemini response was not valid JSON');
  }
  const verdict = String(obj.verdict ?? '').toUpperCase() as Verdict;
  if (!VERDICTS.includes(verdict)) throw new GeminiError('bad verdict', `Unexpected verdict "${obj.verdict}"`);
  const conf = Math.round(Number(obj.confidence));
  if (!Number.isFinite(conf)) throw new GeminiError('bad confidence', 'Confidence missing');
  const steps = Array.isArray(obj.steps) ? obj.steps.map((s) => String(s).replace(/^\s*\d+[.)]\s*/, '')).filter(Boolean).slice(0, 5) : [];
  if (typeof obj.summary !== 'string' || steps.length === 0) throw new GeminiError('missing fields', 'Summary or steps missing');
  return { verdict, confidence: Math.max(0, Math.min(100, conf)), summary: obj.summary, steps };
}

/** Server-side proxy (/api/gemini) that holds GEMINI_API_KEY. The browser never sees the key. */
export async function callGeminiServer(opts: { model: string; userText: string; json?: boolean; timeoutMs?: number }): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? TIMEOUT_MS);
  try {
    const res = await fetch('/api/gemini', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: opts.json === false ? 'ping' : 'triage', model: opts.model, userText: opts.userText }),
      signal: controller.signal,
    });
    let j: any = null;
    try { j = await res.json(); } catch { /* ignore */ }
    if (!res.ok) {
      const detail = j?.error?.message ?? j?.detail ?? j?.error ?? '';
      const short = res.status === 501 ? 'server key not set' : res.status === 404 ? 'model not found (404)' : res.status === 400 || res.status === 403 ? `invalid key or request (${res.status})` : res.status === 429 ? 'rate limited (429)' : res.status === 504 ? 'timeout' : `HTTP ${res.status}`;
      throw new GeminiError(short, `HTTP ${res.status}${detail ? `: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}` : ''}`);
    }
    return j;
  } catch (err) {
    if (err instanceof GeminiError) throw err;
    if ((err as Error)?.name === 'AbortError') throw new GeminiError('timeout', `No response within ${(opts.timeoutMs ?? TIMEOUT_MS) / 1000}s`);
    throw new GeminiError('network error', (err as Error)?.message || 'Network error');
  } finally {
    clearTimeout(timer);
  }
}

/** Asks the server whether GEMINI_API_KEY is configured. */
export async function serverGeminiConfigured(timeoutMs = 4000): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch('/api/gemini', { signal: controller.signal, headers: { Accept: 'application/json' } });
    if (!res.ok || !(res.headers.get('content-type') ?? '').includes('json')) return false;
    const j = await res.json();
    return j?.configured === true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export async function callGemini(opts: { apiKey: string; model: string; userText: string; system?: string; json?: boolean; timeoutMs?: number }): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? TIMEOUT_MS);
  const body: Record<string, unknown> = {
    contents: [{ role: 'user', parts: [{ text: opts.userText }] }],
    generationConfig: opts.json === false
      ? { temperature: 0 }
      : {
          temperature: 0.2,
          responseMimeType: 'application/json',
          responseSchema: {
            type: 'OBJECT',
            properties: {
              verdict: { type: 'STRING', enum: VERDICTS },
              confidence: { type: 'INTEGER' },
              summary: { type: 'STRING' },
              steps: { type: 'ARRAY', items: { type: 'STRING' } },
            },
            required: ['verdict', 'confidence', 'summary', 'steps'],
          },
        },
  };
  if (opts.system) body.systemInstruction = { parts: [{ text: opts.system }] };
  try {
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(opts.model)}:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': opts.apiKey },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) {
      let detail = '';
      try {
        const j = await res.json();
        detail = j?.error?.message ?? '';
      } catch { /* ignore */ }
      const short = res.status === 404 ? 'model not found (404)' : res.status === 400 || res.status === 403 ? `invalid key or request (${res.status})` : res.status === 429 ? 'rate limited (429)' : `HTTP ${res.status}`;
      throw new GeminiError(short, `HTTP ${res.status}${detail ? `: ${detail}` : ''}`);
    }
    return await res.json();
  } catch (err) {
    if (err instanceof GeminiError) throw err;
    if ((err as Error)?.name === 'AbortError') throw new GeminiError('timeout', `No response within ${(opts.timeoutMs ?? TIMEOUT_MS) / 1000}s`);
    throw new GeminiError('network error', (err as Error)?.message || 'Network error');
  } finally {
    clearTimeout(timer);
  }
}

/** Tiny prompt used by Settings → Test Connection. */
export async function testConnection(apiKey: string, model: string, server = false): Promise<{ ok: true; ms: number; reply: string } | { ok: false; ms: number; error: string }> {
  const t0 = performance.now();
  if (!apiKey && !server) return { ok: false, ms: 0, error: 'No API key entered' };
  try {
    const json = (apiKey
      ? await callGemini({ apiKey, model, userText: 'Reply with the single word: ready', json: false })
      : await callGeminiServer({ model, userText: 'ping', json: false })) as { candidates?: { content?: { parts?: { text?: string }[] } }[] };
    const reply = json?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? '(empty reply)';
    return { ok: true, ms: Math.round(performance.now() - t0), reply };
  } catch (e) {
    return { ok: false, ms: Math.round(performance.now() - t0), error: (e as Error).message };
  }
}
