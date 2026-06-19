// cache-bust: 20260619-234800 wc-prod-v8 prod promote (from staging wc-v301-invrelink): Convert to Invoice now self-heals when a QB invoice already exists/was deleted. On invoice_already_exists, the app calls POST /api/qb-invoice-relink to resolve the existing QB invoice by number, stamp full QB linkage + status onto the appointment (job leaves "Ready to Invoice"), and opens that exact invoice via a working "Open Invoice" toast link. Server-side (already on Railway) self-heals a stale lock when the invoice was deleted in QB. Plus prior v300 popup-safe success toast. bundle index-Br4IR-yq.js / index-hvC_Rh4Z.css (CSS unchanged). auth-layer.js untouched. Revert tag: prod-pre-invrelink-20260619-234752 @ c736bff9.
const CACHE = "wc-prod-v8";
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
