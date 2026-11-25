// Vercel Edge Function: server-side Gemini proxy. Reads GEMINI_API_KEY from the project's
// environment variables so the key is never shipped to the browser.
import { handleGemini } from './_core';

export const config = { runtime: 'edge' };

declare const process: { env: Record<string, string | undefined> };

export default async function handler(req: Request): Promise<Response> {
  const body = req.method === 'POST' ? await req.text() : undefined;
  const { status, body: out } = await handleGemini(req.method, body, process.env.GEMINI_API_KEY);
  return new Response(JSON.stringify(out), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}
