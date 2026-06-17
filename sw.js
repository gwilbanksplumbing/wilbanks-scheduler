// cache-bust: 20260617-020500 wc-prod-v5 prod promote: QB invoice notes->CustomerMemo + ready-gated tab open (no blank-tab auto-open; one-click 'Open in QuickBooks' when QB index not warm). bundle index-CjgSd2LL.js / index-hvC_Rh4Z.css (from index-ClK6eIvb.js). auth-layer.js untouched.
const CACHE = "wc-prod-v5";
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
