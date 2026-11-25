// Riskbyte service worker: keeps the app shell in Cache Storage so the console opens even offline.
// Platform data is stored separately (localStorage + the 'riskbyte-data-v1' cache) by the app itself.
const SHELL = 'riskbyte-shell-v1';

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(SHELL).then((c) => c.addAll(['/', '/index.html', '/favicon.svg'])).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('riskbyte-shell-') && k !== SHELL).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/__riskbyte__/')) return;

  // Pages: network first, fall back to the cached shell.
  if (e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request)
        .then((res) => { const copy = res.clone(); caches.open(SHELL).then((c) => c.put('/index.html', copy)); return res; })
        .catch(() => caches.match('/index.html')),
    );
    return;
  }
  // Hashed build assets: cache first.
  if (url.pathname.startsWith('/assets/') || url.pathname === '/favicon.svg') {
    e.respondWith(
      caches.match(e.request).then((hit) => hit || fetch(e.request).then((res) => {
        const copy = res.clone();
        caches.open(SHELL).then((c) => c.put(e.request, copy));
        return res;
      })),
    );
  }
});
