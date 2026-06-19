// cache-bust: 20260619-172300 wc-prod-v6 prod promote (from staging wc-v298-custtype): New Contact form required Residential/Commercial type picker (commercial = company name primary identity + contact/bill-to person, both required; residential = person name is identity source) + explicit customer_type so server scopes duplicate check by type (commercial bill-to can also be created as their own residential customer) + commercial-first appointment card name ordering. bundle index-CZXHMJLP.js / index-hvC_Rh4Z.css (from index-CjgSd2LL.js). auth-layer.js untouched. Revert tag: prod-pre-custtype-20260619-172300 @ 56fdb24.
const CACHE = "wc-prod-v6";
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
