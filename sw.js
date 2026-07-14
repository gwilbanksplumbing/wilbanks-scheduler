// cache-bust: 20260714-153800 wc-prod-v13 prod promote (from staging wc-staging-descformat-20260714-150800): line-item description formatting preserved (white-space:pre-wrap) in client legacy builders; the authoritative preview/email is server-rendered (wc-v314 in routes.ts, already live). bundle index-D7MK95F8.js; auth-layer.js untouched (wc-v254a). Server revert tag: prod-pre-descformat-20260714-151214.
const CACHE = "wc-prod-v13";
const OFFLINE = ["/", "/index.html"];
self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(OFFLINE)));
  self.skipWaiting();
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", e => {
  if (e.request.url.includes("/api/") || e.request.url.includes("/uploads/")) return;
  e.respondWith(
    fetch(e.request).then(res => { caches.open(CACHE).then(c => c.put(e.request, res.clone())); return res; })
      .catch(() => caches.match(e.request))
  );
});
