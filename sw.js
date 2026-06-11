// cache-bust: 20260611-0942 wc-v270r prod promote: HOTFIX for the live List-view crash "Cannot read properties of null (reading 'replace')". usePreference get() now falls back to default for a null-persisted pref (statusFilter was null -> Dashboard.tsx:2002 statusFilter.replace crashed the whole app). Confirmed via source-map decode of the live stack trace + isolated test; verified on staging. Also carries the harmless wc-v270q global-search null-coalescing. New JS index-D2ijUvMb.js (CSS index-D4OTVTTE.css unchanged). auth-layer.js BUILD_VERSION untouched (wc-v254a).
const CACHE = "wc-v270r"; // prod hotfix 2026-06-11: null-pref List-view crash fix (+ wc-v270q global-search hardening)
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
