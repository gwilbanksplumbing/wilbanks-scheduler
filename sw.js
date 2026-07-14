// cache-bust: 20260714-142700 wc-prod-v12 prod promote (from staging wc-staging-sendtoast-20260714-141500): send toast now shows the server-resolved recipient (sentTo) so every estimate/invoice send visibly confirms which address it emailed. Pairs with server wc-v311 (live send-to), wc-v312 (Bill To live email), wc-v313 (sentTo in response). JS+CSS swap (index-BdmJF5_P.js); auth-layer.js untouched (wc-v254a). Server revert tag: prod-pre-sendtoast-20260714-142102.
const CACHE = "wc-prod-v12";
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
