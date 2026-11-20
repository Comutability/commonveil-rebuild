// Commonveil's service worker (docs/NOTIFICATIONS.md, docs/INSTALLING.md).
//
// It does two things:
//   1. Keeps the app's own code (its pages, scripts, styles, icons) so the app opens quickly and
//      even without a connection. It never keeps anything from the backend: no messages, no keys,
//      no profiles, nothing anyone sends you.
//   2. Shows push notifications that say only that there's something new. A push carries its kind
//      and a one-time code, nothing else; tapping it opens the app, which asks (signed in) where to go.
// Bumping these names is also what tells every browser there's a new version to fetch: the file's
// bytes change, so a new worker installs, and the old kept copies are cleared when it takes over.
const SHELL = "cv-shell-v3";
const ASSETS = "cv-assets-v3";
const MAX_ASSETS = 300;

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(SHELL)
      .then((c) => c.addAll(["/", "/manifest.webmanifest", "/favicon.svg", "/icons/icon-192.png"]))
      .catch(() => {}),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) if (![SHELL, ASSETS].includes(key)) await caches.delete(key);
      await self.clients.claim();
    })(),
  );
});

// The app asks a waiting new version to take over ("Update now").
self.addEventListener("message", (event) => {
  if (event.data?.type === "skip-waiting") self.skipWaiting();
});

// Never kept: anything that isn't the app's own code.
const NEVER = [/^\/api\//, /^\/cvp\//, /^\/\.well-known\//, /^\/u\//, /^\/sw\.js$/];

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || NEVER.some((re) => re.test(url.pathname))) return;

  // Pages: the network first (so updates arrive), the kept copy when offline.
  if (req.mode === "navigate") {
    event.respondWith(
      (async () => {
        try {
          const res = await fetch(req);
          if (res.ok && (res.headers.get("content-type") || "").includes("text/html")) {
            const cache = await caches.open(SHELL);
            await cache.put("/", res.clone());
          }
          return res;
        } catch {
          return (await caches.match("/", { cacheName: SHELL })) || new Response("Commonveil is offline.", { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" } });
        }
      })(),
    );
    return;
  }

  // Built files have their content's fingerprint in their names, so a kept copy is always right.
  if (url.pathname.startsWith("/assets/") || url.pathname.startsWith("/icons/") || url.pathname === "/favicon.svg" || url.pathname === "/manifest.webmanifest") {
    event.respondWith(
      (async () => {
        const kept = await caches.match(req);
        if (kept) return kept;
        const res = await fetch(req);
        if (res.ok && res.type === "basic") {
          const cache = await caches.open(ASSETS);
          await cache.put(req, res.clone());
          const keys = await cache.keys();
          for (const old of keys.slice(0, Math.max(0, keys.length - MAX_ASSETS))) await cache.delete(old);
        }
        return res;
      })(),
    );
  }
});

// ---------- notifications ----------

/** Settings the app mirrors here: quiet hours and focus (src/lib/pwa/push.js). Kept on this device. */
function readPrefs() {
  return new Promise((resolve) => {
    let open;
    try {
      open = indexedDB.open("commonveil-push", 1);
    } catch {
      resolve({});
      return;
    }
    open.onupgradeneeded = () => open.result.createObjectStore("kv");
    open.onerror = () => resolve({});
    open.onsuccess = () => {
      try {
        const get = open.result.transaction("kv", "readonly").objectStore("kv").get("prefs");
        get.onsuccess = () => resolve(get.result || {});
        get.onerror = () => resolve({});
      } catch {
        resolve({});
      }
    };
  });
}

function quietNow(p, now = new Date()) {
  if (p.focusUntil && now.getTime() < p.focusUntil) return true;
  if (!p.quiet || p.quietFrom === p.quietTo) return false;
  const m = now.getHours() * 60 + now.getMinutes();
  return p.quietFrom < p.quietTo ? m >= p.quietFrom && m < p.quietTo : m >= p.quietFrom || m < p.quietTo;
}

const WORDS = { message: "New message", conversation: "New message", activity: "New activity", mention: "New activity", test: "Notifications are on. This is all they'll ever say." };

self.addEventListener("push", (event) => {
  event.waitUntil(
    (async () => {
      let p = {};
      try {
        p = event.data ? event.data.json() : {};
      } catch {
        p = {};
      }
      // Say so to any window that's open, first. A phone can show nothing at all for reasons the
      // site can't see, and this is how the app knows the push got here at least.
      try {
        for (const w of await self.clients.matchAll({ type: "window", includeUncontrolled: true })) w.postMessage({ type: "push-received", kind: p.k });
      } catch {
        // No window open: there's nobody to tell.
      }
      // Quiet hours live in this device's own storage, which a phone that has just woken up can be
      // slow to answer. A notification that never appears is worse than one that isn't silenced.
      const prefs = await Promise.race([readPrefs(), new Promise((r) => setTimeout(() => r({}), 1500))]);
      // No channel ids or preferences leave the device. An unknown channel defaults to quiet,
      // rather than allowing a server's activity to leak onto a locked screen.
      const serverActivity = p.k === "activity" || p.k === "mention";
      const level = serverActivity ? (prefs.pushLevels?.[p.m] || "none") : null;
      const muted = Boolean((p.m && Array.isArray(prefs.muted) && prefs.muted.includes(p.m)) ||
        (serverActivity && (level === "none" || (level === "mentions" && p.k !== "mention"))));
      const silent = muted || quietNow(prefs);
      const body = WORDS[p.k] || "New activity";
      // A test gets its own tag: one still sitting in the shade would be replaced by the new one
      // instead of alerting, which looks exactly like the test not working.
      const tag = p.k === "test" ? "commonveil-test" : "commonveil";
      // One notification at a time, replaced by the next: fewer records left on the device.
      try {
        await self.registration.showNotification("Commonveil", {
          body,
          tag,
          renotify: !silent,
          silent,
          icon: "/icons/icon-192.png",
          badge: "/icons/badge-96.png",
          data: { c: typeof p.c === "string" ? p.c : "" },
        });
      } catch {
        // The phone refused those options: the plainest notification there is beats none.
        try {
          await self.registration.showNotification("Commonveil", { body, tag, data: { c: typeof p.c === "string" ? p.c : "" } });
        } catch {
          // Nothing left to try on this device.
        }
      }
      if (muted) for (const n of await self.registration.getNotifications({ tag })) n.close();
      if (!muted && navigator.setAppBadge) navigator.setAppBadge().catch(() => {});
    })(),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const code = event.notification.data?.c || "";
  const target = code ? `/app?push=${encodeURIComponent(code)}` : "/app";
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      const open = windows.find((w) => new URL(w.url).origin === self.location.origin);
      if (open) {
        await open.focus();
        open.postMessage({ type: "push-open", code });
        return;
      }
      await self.clients.openWindow(target);
    })(),
  );
});
