// cache-bust: 20260610-2302 wc-v270p prod promote: Customer card overhaul (Completed/Open clickable count pills, card body no longer click-to-expand, working chevron "show all" toggle) + tech avatar pipeline Phases A-D (photos in chips/Settings/Tech-view/Map side-list+popups+pins, R2 custom-domain assets) + SaaS asset-host refactor. Server already live at wc-v270k (History/PDF job-match + Outstanding-tile balance-due fixes).
const CACHE = "wc-v270p"; // promote 2026-06-10: customer-card affordances (wc-v270o/p) + tech avatars A-D (wc-v270h-m) + asset-host refactor (wc-v270n); server wc-v270k already live
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
