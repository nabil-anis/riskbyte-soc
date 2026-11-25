// Vercel Edge Function: live threat-intel feeds, cached at the edge for an hour.
import { fetchIntel } from './_intel';

export const config = { runtime: 'edge' };

export default async function handler(): Promise<Response> {
  const payload = await fetchIntel();
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, s-maxage=3600, stale-while-revalidate=600' },
  });
}
