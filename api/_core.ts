// Shared server-side Gemini proxy logic. Used by the Vercel function (api/gemini.ts)
// and by the Vite dev server middleware (vite.config.ts). The API key never reaches the browser.

export const SYSTEM_INSTRUCTION =
  'You are a SOC triage assistant. Given one redacted security alert and its evidence, return a verdict (MALICIOUS, SUSPICIOUS or BENIGN), a confidence 0-100, a plain-English summary of at most 3 sentences, and 3 to 5 numbered investigation steps. Use only the evidence provided. Entity tokens like [REDACTED_IP_1] are placeholders; keep them as written. Never invent indicators. You only propose; a human approves any action.';

const RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    verdict: { type: 'STRING', enum: ['MALICIOUS', 'SUSPICIOUS', 'BENIGN'] },
    confidence: { type: 'INTEGER' },
    summary: { type: 'STRING' },
    steps: { type: 'ARRAY', items: { type: 'STRING' } },
  },
  required: ['verdict', 'confidence', 'summary', 'steps'],
};

const MODEL_RE = /^[a-z0-9][a-z0-9.\-]{1,60}$/i;
const MAX_TEXT = 24_000;

export interface ProxyResult {
  status: number;
  body: unknown;
}

/**
 * GET  → { configured, provider }
 * POST { mode: 'triage' | 'ping', model, userText } → Gemini generateContent response (passed through)
 * Only two fixed request shapes are allowed so the endpoint can't be used as a general-purpose proxy.
 */
export async function handleGemini(method: string, rawBody: string | undefined, apiKey: string | undefined): Promise<ProxyResult> {
  const key = (apiKey ?? '').trim();
  if (method === 'GET') return { status: 200, body: { configured: !!key, provider: 'gemini', keySource: 'server env GEMINI_API_KEY' } };
  if (method !== 'POST') return { status: 405, body: { error: 'method not allowed' } };
  if (!key) return { status: 501, body: { error: 'not configured', detail: 'GEMINI_API_KEY is not set on the server' } };

  let req: { mode?: string; model?: string; userText?: string };
  try {
    req = JSON.parse(rawBody || '{}');
  } catch {
    return { status: 400, body: { error: 'invalid JSON' } };
  }
  const model = String(req.model || 'gemini-2.5-flash');
  if (!MODEL_RE.test(model)) return { status: 400, body: { error: 'invalid model name' } };
  const mode = req.mode === 'ping' ? 'ping' : 'triage';
  const userText = mode === 'ping' ? 'Reply with the single word: ready' : String(req.userText ?? '');
  if (!userText || userText.length > MAX_TEXT) return { status: 400, body: { error: 'userText missing or too long' } };

  const payload: Record<string, unknown> = {
    contents: [{ role: 'user', parts: [{ text: userText }] }],
    generationConfig: mode === 'ping'
      ? { temperature: 0 }
      : { temperature: 0.2, responseMimeType: 'application/json', responseSchema: RESPONSE_SCHEMA },
  };
  if (mode === 'triage') payload.systemInstruction = { parts: [{ text: SYSTEM_INSTRUCTION }] };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 11_000);
  try {
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await res.text();
    let body: unknown;
    try { body = JSON.parse(text); } catch { body = { error: 'upstream returned non-JSON' }; }
    return { status: res.status, body };
  } catch (e) {
    const aborted = (e as Error)?.name === 'AbortError';
    return { status: aborted ? 504 : 502, body: { error: aborted ? 'upstream timeout' : 'upstream unreachable' } };
  } finally {
    clearTimeout(timer);
  }
}
