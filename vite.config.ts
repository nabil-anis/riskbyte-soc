import { defineConfig, loadEnv, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { handleGemini } from './api/_core';
import { fetchIntel } from './api/_intel';

type Mw = { use: (path: string, fn: (req: any, res: any) => void) => void };

/**
 * Serves the same /api routes as the Vercel functions during `npm run dev` / `npm run preview`.
 * GEMINI_API_KEY is read from .env.local and never sent to the browser.
 */
function apiRoutes(key: string | undefined): Plugin {
  let intelCache: { at: number; body: unknown } | null = null;
  const json = (res: any, status: number, body: unknown) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(body));
  };
  const mount = (app: Mw) => {
    app.use('/api/gemini', (req, res) => {
      let raw = '';
      req.on('data', (c: Buffer) => (raw += c));
      req.on('end', async () => {
        const out = await handleGemini(req.method ?? 'GET', raw, key);
        json(res, out.status, out.body);
      });
    });
    app.use('/api/intel', async (_req, res) => {
      if (!intelCache || Date.now() - intelCache.at > 3600_000) intelCache = { at: Date.now(), body: await fetchIntel() };
      json(res, 200, intelCache.body);
    });
    app.use('/api/whoami', (req, res) => {
      const ip = String(req.headers['x-forwarded-for'] ?? req.socket?.remoteAddress ?? 'unknown').split(',')[0].replace('::ffff:', '').trim();
      json(res, 200, { ip: ip === '::1' ? '127.0.0.1' : ip, country: undefined, userAgent: req.headers['user-agent'], source: 'dev-server' });
    });
  };
  return {
    name: 'riskbyte-api',
    configureServer(server) { mount(server.middlewares); },
    configurePreviewServer(server) { mount(server.middlewares); },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [react(), apiRoutes(env.GEMINI_API_KEY || process.env.GEMINI_API_KEY)],
    test: { environment: 'node', include: ['src/tests/**/*.test.ts'] },
  } as any;
});
