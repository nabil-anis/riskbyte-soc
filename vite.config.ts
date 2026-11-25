import { defineConfig, loadEnv, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { handleGemini } from './api/_core';

/** Serves /api/gemini during `npm run dev` / `npm run preview` using GEMINI_API_KEY from .env.local. */
function geminiProxy(key: string | undefined): Plugin {
  const mount = (app: { use: (path: string, fn: (req: any, res: any) => void) => void }) =>
    app.use('/api/gemini', (req, res) => {
      let raw = '';
      req.on('data', (c: Buffer) => (raw += c));
      req.on('end', async () => {
        const out = await handleGemini(req.method ?? 'GET', raw, key);
        res.statusCode = out.status;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(out.body));
      });
    });
  return {
    name: 'riskbyte-gemini-proxy',
    configureServer(server) { mount(server.middlewares); },
    configurePreviewServer(server) { mount(server.middlewares); },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [react(), geminiProxy(env.GEMINI_API_KEY || process.env.GEMINI_API_KEY)],
    test: { environment: 'node', include: ['src/tests/**/*.test.ts'] },
  } as any;
});
