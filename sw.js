// Wilbanks Company — Service Worker (Push + Cache Busting)
// Merged: prod push-notification SW (badge counts, push events) + preview's
// wc-vNNN cache-busting block so prod can force-refresh client bundles on
// each deploy without losing push.

// ─────────────────────────────────────────────────────────────────────────
// Cache version — bump on every prod deploy to force clients to fetch the
// new index.html / bundle. On activate, all caches except this one are
// deleted, and the SW immediately claims all open clients.
// ─────────────────────────────────────────────────────────────────────────
const CACHE = "wc-v130";
const OFFLINE = [
  "/wilbanks-scheduler/",
  "/wilbanks-scheduler/index.html",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(OFFLINE)));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          // Keep the badge cache; only purge old wc-vNNN snapshots.
          .filter((k) => k !== CACHE && k !== "wilbanks-badge")
          .map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  // Don't intercept API or upload requests — these must always hit the network
  // for fresh data / auth-aware responses.
  if (e.request.url.includes("/api/") || e.request.url.includes("/uploads/")) return;
  // Only handle GET — POST/PUT/PATCH/DELETE must go straight to the network.
  if (e.request.method !== "GET") return;
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        // Stash a copy in the cache for offline fallback. Clone before
        // returning because the original body can only be read once.
        const copy = res.clone();
        caches.open(CACHE).then((c) => {
          try { c.put(e.request, copy); } catch {}
        });
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});

// ─────────────────────────────────────────────────────────────────────────
// Push notifications (unchanged from prod). Keeps badge count + tap-to-focus
// behavior on desktop and iPhone PWAs.
// ─────────────────────────────────────────────────────────────────────────
const BADGE_KEY = "wilbanks_badge_count";

async function getBadgeCount() {
  const cache = await caches.open("wilbanks-badge");
  const resp = await cache.match(BADGE_KEY);
  if (!resp) return 0;
  const text = await resp.text();
  return parseInt(text) || 0;
}

async function setBadgeCount(n) {
  const cache = await caches.open("wilbanks-badge");
  await cache.put(BADGE_KEY, new Response(String(n)));
  if (navigator.setAppBadge) {
    if (n > 0) await navigator.setAppBadge(n);
    else await navigator.clearAppBadge();
  }
}

self.addEventListener("push", function (event) {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: "Wilbanks Company", body: event.data ? event.data.text() : "" };
  }

  const title = data.title || "Wilbanks Company";
  const options = {
    body: data.body || "",
    icon: "/wilbanks-scheduler/apple-touch-icon.png",
    badge: "/wilbanks-scheduler/icon-192.png",
    tag: data.appointmentId ? `appt-${data.appointmentId}` : "wilbanks-notification",
    requireInteraction: true,
    data: { appointmentId: data.appointmentId },
  };

  event.waitUntil(
    getBadgeCount().then(async (count) => {
      const newCount = count + 1;
      await setBadgeCount(newCount);
      return self.registration.showNotification(title, options);
    })
  );
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  // Clear badge when user taps the notification
  event.waitUntil(
    getBadgeCount().then(async (count) => {
      const notifications = await self.registration.getNotifications();
      const remaining = Math.max(0, count - 1);
      await setBadgeCount(remaining);
    }).then(() => {
      return clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (clientList) {
        for (const client of clientList) {
          if (client.url && "focus" in client) {
            return client.focus();
          }
        }
        if (clients.openWindow) {
          return clients.openWindow("https://gwilbanksplumbing.github.io/wilbanks-scheduler/");
        }
      });
    })
  );
});
