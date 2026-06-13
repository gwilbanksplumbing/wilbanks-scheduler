// cache-bust: 20260613-1900 wc-prod-v3: Promote staging wc-v293..v293b -> prod. Bundle-swap only (index-CoRKHDaa.js / index-hvC_Rh4Z.css; CSS hash changed this cycle). Carries: map duplicate-row client dedupe (v293), Map View date-picker now CLOSES on day select (v293a), and calendar HOVER + selected/today restyling app-wide (v293b: hovered day stands out, selected = bold orange fill+ring, today = subtle outline ring). Shared server already carries the map effective-date fix (wc-v294: completed jobs map to completed_at day, not scheduled day). auth-layer.js BUILD_VERSION untouched (wc-v254a). Staging bundle verified byte-identical to src build.
const CACHE = "wc-prod-v3";
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
