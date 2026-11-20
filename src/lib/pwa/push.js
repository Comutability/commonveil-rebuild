// Push notifications on this device (docs/NOTIFICATIONS.md). They say only "New message" or "New
// activity", even to this device; tapping one opens the app, which asks where to go.
import { callFn } from "@/lib/api";
import { workerUrl } from "@/lib/pwa/app";
import { pushHint } from "@/lib/pwa/browser";

const supported = () => typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
const KEY = "commonveil_push_secret";
// A phone can take a moment to start the service worker behind the app: long enough for a slow
// connection, short enough that a worker which never starts says so instead of spinning forever.
const SW_WAIT_MS = 12_000;
// Whether this visit has already told the site which browser this is.
let told = false;

export const pushSupported = supported;

function fromB64url(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
const toB64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function registration() {
  if (!supported()) return null;
  // Started at launch (lib/pwa/app.js). On a phone it can have been closed, or never started at
  // all: start it here, and don't wait to be controlling the page, so turning them on isn't a
  // dead end.
  let reg = await navigator.serviceWorker.getRegistration("/").catch(() => null);
  if (!reg) reg = await navigator.serviceWorker.register(workerUrl(), { scope: "/" }).catch(() => null);
  if (!reg) return null;
  if (reg.active) return reg;
  return Promise.race([navigator.serviceWorker.ready, new Promise((r) => setTimeout(() => r(null), SW_WAIT_MS))]);
}

/** This browser's own key for mute keys, made once and kept on the device. */
function muteSecret() {
  try {
    const kept = window.localStorage.getItem(KEY);
    if (kept) return kept;
    const made = toB64url(crypto.getRandomValues(new Uint8Array(32)));
    window.localStorage.setItem(KEY, made);
    return made;
  } catch {
    return toB64url(crypto.getRandomValues(new Uint8Array(32)));
  }
}

/** Tell the site where to push to this browser. Saying it again changes nothing. */
async function tellServer(sub) {
  const json = sub.toJSON();
  await callFn("notifications", { action: "subscribe", endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth, mute_secret: muteSecret() });
}

/** Whether this browser is subscribed now. */
export async function pushState() {
  if (!supported()) return "unsupported";
  if (Notification.permission === "denied") return "blocked";
  const reg = await Promise.race([registration(), new Promise((r) => setTimeout(() => r(null), 3000))]);
  if (!reg) return "unavailable";
  const sub = await Promise.race([reg.pushManager.getSubscription(), new Promise((r) => setTimeout(() => r(null), 3000))]);
  if (!sub) return "off";
  // This browser is subscribed, so the site should know it. A turn-on can be interrupted (a phone
  // that slept, a dropped connection), which leaves the browser subscribed and nothing able to
  // arrive: say it again, once per visit, and the site writes only if something has changed.
  if (!told) {
    try {
      await tellServer(sub);
      told = true;
    } catch {
      // Offline, or signed out: the next visit tries again.
    }
  }
  return "on";
}

/** Ask permission, subscribe this browser, and tell the site where to push. */
export async function turnOnPush() {
  if (!supported()) throw new Error("This browser can't receive push notifications. On a phone they work in Safari (iPhone and iPad, once Commonveil is on your Home Screen) or Chrome (Android).");
  const permission = await Notification.requestPermission();
  if (permission !== "granted") throw new Error(permission === "denied" ? "Notifications are blocked for this site. Allow them in your browser's site settings, then try again." : "Notifications weren't allowed.");
  const reg = await registration();
  if (!reg) throw new Error("Your browser hasn't started Commonveil's background service yet. Try again in a moment, or close the app and open it again.");
  const { public_key } = await callFn("notifications", { action: "key" });
  let sub = await reg.pushManager.getSubscription();
  if (sub) await sub.unsubscribe().catch(() => {});
  try {
    sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: fromB64url(public_key) });
  } catch {
    // Brave with its own push service turned off, or a phone that won't let this browser post
    // notifications: the browser's own words mean nothing here, so say which switch to look for.
    throw new Error(`This browser wouldn't set up notifications. ${pushHint()}`);
  }
  try {
    await tellServer(sub);
    told = true;
  } catch (err) {
    // Unless the site has this browser's address nothing can arrive: undo, rather than say "On".
    await sub.unsubscribe().catch(() => {});
    throw err;
  }
  // Straight away, prove it: a browser can hold notifications back without telling the site
  // (Brave's own push setting, a phone that won't let this browser post them). Better to find out
  // here, while the person is looking, than for them to wonder why nothing ever arrives.
  return sendTestPush();
}

export async function turnOffPush() {
  const reg = await registration();
  const sub = await reg?.pushManager.getSubscription();
  if (sub) {
    await callFn("notifications", { action: "unsubscribe", endpoint: sub.endpoint }).catch(() => {});
    await sub.unsubscribe().catch(() => {});
  }
}

/**
 * Send the site's test push and then watch this device for it: true if it turned up, false if it
 * didn't within the wait, null if this browser can't be asked. The device's own list of showing
 * notifications is the only honest answer to "is it working here?".
 */
export async function sendTestPush(waitMs = 12_000) {
  const reg = await registration().catch(() => null);
  const look = async () => {
    try {
      return await reg.getNotifications({ tag: "commonveil" });
    } catch {
      return null;
    }
  };
  if (!reg || typeof reg.getNotifications !== "function") return null;
  // Clear any earlier one, so only something new counts as an arrival.
  for (const old of (await look()) || []) old.close();
  await callFn("notifications", { action: "test" });
  const until = Date.now() + waitMs;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 500));
    const seen = await look();
    if (seen === null) return null;
    if (seen.length) return true;
  }
  return false;
}

/** Mirror quiet hours and focus for the service worker, which can't read the app's storage. */
export function mirrorPushPrefs(alerts) {
  if (typeof indexedDB === "undefined") return;
  try {
    const open = indexedDB.open("commonveil-push", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("kv");
    open.onsuccess = () => {
      try {
        const tx = open.result.transaction("kv", "readwrite");
        tx.objectStore("kv").put({ quiet: alerts.quiet, quietFrom: alerts.quietFrom, quietTo: alerts.quietTo, focusUntil: alerts.focusUntil, muted: [] }, "prefs");
      } catch {
        // Nothing to mirror into: notifications just aren't silenced on schedule.
      }
    };
  } catch {
    // As above.
  }
}

/** Where a tapped notification leads (the code is used once). */
export async function openFromPush(code) {
  try {
    const { path } = await callFn("notifications", { action: "open", code });
    return typeof path === "string" && path.startsWith("/app") ? path : "/app";
  } catch {
    return "/app";
  }
}