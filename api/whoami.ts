// Vercel Edge Function: the caller's real public IP and approximate location (from Vercel's edge headers).
export const config = { runtime: 'edge' };

export default async function handler(req: Request): Promise<Response> {
  const h = req.headers;
  const ip = (h.get('x-real-ip') || h.get('x-forwarded-for')?.split(',')[0] || '').trim() || 'unknown';
  const dec = (v: string | null) => { try { return v ? decodeURIComponent(v) : undefined; } catch { return v ?? undefined; } };
  const body = {
    ip,
    country: h.get('x-vercel-ip-country') || undefined,
    region: dec(h.get('x-vercel-ip-country-region')),
    city: dec(h.get('x-vercel-ip-city')),
    userAgent: h.get('user-agent') || undefined,
    source: 'vercel-edge',
  };
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
