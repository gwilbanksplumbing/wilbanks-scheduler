// cache-bust: 20260712-224239 wc-prod-v11 prod promote (from staging wc-staging-bookhours2-20260712-223431): Bookable-hours enforcement front-end. Calendar Week/Day grids, By Tech swim-lane, and New Job time picker all read Settings business_hours_start/end and only allow starts in [from, until) (last start = until-1; end may spill past until). Fully settings-driven, live re-read on Settings change. Server-side 409 guard already live on shared Railway. JS-only swap (index-C5BKEUm8.js); CSS index-BJBnrrQT.css unchanged; auth-layer.js untouched (wc-v254a). Revert tag: prod-pre-bookhours-20260712-224200 @ 8443d3be.
const CACHE = "wc-prod-v11";
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
