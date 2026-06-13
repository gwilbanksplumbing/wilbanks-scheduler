// cache-bust: 20260613-1830 wc-prod-v2: Promote staging wc-v278..v292 -> prod. Bundle-swap only (index-BYeSUEHy.js / index-DVFzr4l9.css). Carries: estimate/invoice card rework (v278-v286), single-invoice-door enforcement (v287-v290: invoices minted ONLY via Ready-to-Invoice, card=View+Resend, builder estimate-only, HVAC Convert routes to one send flow), calendar hide-completed-jobs toggle (v291), and admin-only Void & re-bill action (v292). Shared server already carries invoice-lock 409 guards + QB blank-tab URL fix + void-invoice endpoint. auth-layer.js BUILD_VERSION untouched (wc-v254a). Staging bundle verified byte-identical to src build.
const CACHE = "wc-prod-v2";
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
