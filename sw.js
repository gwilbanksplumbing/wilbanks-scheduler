// cache-bust: 20260610-1820 wc-v270g prod promote: reschedule dialog UX (no soft-warn amber, only hard-block inside [start,end)) + Send Invoice frontend helper (RtiActions totalAlreadyPaid). Server wc-v270g already live: send-gmail amtPaid resolves via DB fallback for patched_estimate.tsx path (Larry-class fix).
const CACHE = "wc-v270g"; // promote 2026-06-10: reschedule UX (wc-v270/a-e) + send-invoice frontend helper (wc-v270f); server wc-v270g already live
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
