// cache-bust: wc-prod-v21 PROD: bulk customer import wizard. Two-phase preview/apply; clean new rows auto-add (collapsed), only duplicates / in-file dups / invalid need review. Bulk dup links skip/merge (no bulk overwrite); overwrite per-row only. Template + Import File buttons + hint on Customers screen. bundle index-CsvE1ovJ.js.
const CACHE = "wc-prod-v21";
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
