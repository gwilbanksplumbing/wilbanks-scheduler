// cache-bust: wc-prod-v20 PROD: Multi-Day/Multi-Hour toggle honors same-day custom durations on BOTH new + edit screens (sends spanOverride). An 8:00 AM-12:00 PM block saves the full span; toggle off still enforces the 2h Scheduling setting. bundle index-CupxxRJi.js.
const CACHE = "wc-prod-v20";
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
