// Real threat intelligence, fetched server-side from public feeds (no API key needed):
//  - abuse.ch Feodo Tracker: botnet command-and-control IPs
//  - OpenPhish community feed: live phishing URLs (reduced to domains)

export interface FeedIndicator {
  value: string;
  type: 'ip' | 'domain';
  category: string;
  confidence: number;
  note: string;
  source: string;
}

export interface IntelPayload {
  fetchedAt: string;
  sources: { name: string; url: string; ok: boolean; count: number; error?: string }[];
  indicators: FeedIndicator[];
}

const FEODO = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
const OPENPHISH = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';

async function get(url: string, ms = 8000): Promise<Response> {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try {
    return await fetch(url, { signal: c.signal, headers: { 'User-Agent': 'riskbyte-soc/1.0' } });
  } finally {
    clearTimeout(t);
  }
}

export async function fetchIntel(): Promise<IntelPayload> {
  const sources: IntelPayload['sources'] = [];
  const indicators: FeedIndicator[] = [];

  try {
    const res = await get(FEODO);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const rows = (await res.json()) as { ip_address: string; port: number; status: string; malware: string; country: string | null; as_name: string | null; last_online: string | null }[];
    for (const r of rows) {
      if (!r.ip_address) continue;
      indicators.push({
        value: r.ip_address, type: 'ip', category: `botnet C2 (${r.malware})`,
        confidence: r.status === 'online' ? 0.95 : 0.8,
        note: `${r.malware} C2 :${r.port} · ${r.status}${r.country ? ` · ${r.country}` : ''}${r.as_name ? ` · ${r.as_name}` : ''}${r.last_online ? ` · last online ${r.last_online}` : ''}`,
        source: 'abuse.ch Feodo Tracker',
      });
    }
    sources.push({ name: 'abuse.ch Feodo Tracker', url: FEODO, ok: true, count: rows.length });
  } catch (e) {
    sources.push({ name: 'abuse.ch Feodo Tracker', url: FEODO, ok: false, count: 0, error: (e as Error).message });
  }

  try {
    const res = await get(OPENPHISH);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const lines = (await res.text()).split('\n').map((l) => l.trim()).filter(Boolean);
    const seen = new Set<string>();
    for (const line of lines) {
      let host = '';
      try { host = new URL(line).hostname.toLowerCase(); } catch { continue; }
      if (!host || seen.has(host)) continue;
      seen.add(host);
      indicators.push({ value: host, type: 'domain', category: 'phishing (live)', confidence: 0.9, note: `Phishing URL seen: ${line.slice(0, 120)}`, source: 'OpenPhish' });
    }
    sources.push({ name: 'OpenPhish', url: OPENPHISH, ok: true, count: seen.size });
  } catch (e) {
    sources.push({ name: 'OpenPhish', url: OPENPHISH, ok: false, count: 0, error: (e as Error).message });
  }

  return { fetchedAt: new Date().toISOString(), sources, indicators: indicators.slice(0, 5000) };
}
