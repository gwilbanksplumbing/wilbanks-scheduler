// cache-bust: 20260612-1834 wc-prod-v1: Promote staging wc-v276 -> prod. Bundle-swap only (index-BqBdUlwk.js / index-BFQRDnJN.css). Carries v271-v276: status-pill legend-match colors, AppointmentDetail 15s poll + focus-refetch, detail-pill overlays fresh calendar-list copy (no lag vs month chip), Settings IA overhaul, Dispatcher Notes on Day-view chips. auth-layer.js BUILD_VERSION untouched (wc-v254a). Verified staging bundle byte-identical to src build.
const CACHE = "wc-prod-v1";
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
