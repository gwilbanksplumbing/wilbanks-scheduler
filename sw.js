// cache-bust: 20260702-174200 wc-prod-v9 prod promote (from staging b8ae674 = wc-v305-thresh-all): (1) Invoice preview modal now uses QB TxnDate for the visible date (was rendering today for resends); qb-invoice-paid Gmail HTML same fix. (2) Send Past Due Notice button on the appointment page opens the same HvacSendInvoiceFlow with an amber Payment Reminder banner and PAST DUE subject line. Server persists past_due_sent_at (ISO-8601) on the appointment; latest send wins. (3) Print button in Invoice + Estimate preview iframe modals calls contentWindow.print() so customer-facing HTML prints (not the dashboard shell). (4) All three invoice-row buttons unified to a neutral outline pill style (transparent bg + subtle border + white text) with a solid blue hover, HVAC and Plumbing branches both. (5) Outstanding drawer gains Send Past Due Invoice button next to Record Payment, same drawer-scoped .wc-ou-pill-btn hover style; row shows Past due sent: MMM D, h:mm A when timestamp exists. (6) Settings Billing outstanding-threshold dropdown gains an All option (value=1) that surfaces every sent-but-unpaid invoice regardless of age; pill and drawer render All when threshold=1. bundle index-prodv9-pastdue.js / index-WxGDSTn6.css. auth-layer.js untouched. Revert tag: prod-pre-v305-20260702-224005 @ b88f236.
const CACHE = "wc-prod-v9";
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
