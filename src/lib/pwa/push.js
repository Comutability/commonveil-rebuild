// Push notifications on this device (docs/NOTIFICATIONS.md). They say only "New message" or "New
// activity", even to this device; tapping one opens the app, which asks where to go.
import { callFn } from "@/lib/api";

const supported = () => typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
const KEY = "commonveil_push_secret";

export const pushSupported = supported;

function fromB64url(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
const toB64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function registration() {
  if (!supported()) return null;
  return navigator.serviceWorker.ready;
}

/** Whether this browser is subscribed now. */
export async function pushState() {
  if (!supported()) return "unsupported";
  if (Notification.permission === "denied") return "blocked";
  const reg = await Promise.race([registration(), new Promise((r) => setTimeout(() => r(null), 3000))]);
  if (!reg) return "unavailable";
  return (await reg.pushManager.getSubscription()) ? "on" : "off";
}

/** Ask permission, subscribe this browser, and tell the site where to push. */
export async function turnOnPush() {
  if (!supported()) throw new Error("This browser can't receive push notifications.");
  const permission = await Notification.requestPermission();
  if (permission !== "granted") throw new Error(permission === "denied" ? "Notifications are blocked for this site. Allow them in your browser's site settings, then try again." : "Notifications weren't allowed.");
  const reg = await registration();
  const { public_key } = await callFn("notifications", { action: "key" });
  let sub = await reg.pushManager.getSubscription();
  if (sub) await sub.unsubscribe().catch(() => {});
  sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: fromB64url(public_key) });
  // Made here: lets this device recognise muted places without a push naming them.
  let secret = "";
  try {
    secret = window.localStorage.getItem(KEY) || "";
    if (!secret) {
      secret = toB64url(crypto.getRandomValues(new Uint8Array(32)));
      window.localStorage.setItem(KEY, secret);
    }
  } catch {
    secret = toB64url(crypto.getRandomValues(new Uint8Array(32)));
  }
  const json = sub.toJSON();
  await callFn("notifications", { action: "subscribe", endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth, mute_secret: secret });
}

export async function turnOffPush() {
  const reg = await registration();
  const sub = await reg?.pushManager.getSubscription();
  if (sub) {
    await callFn("notifications", { action: "unsubscribe", endpoint: sub.endpoint }).catch(() => {});
    await sub.unsubscribe().catch(() => {});
  }
}

export const sendTestPush = () => callFn("notifications", { action: "test" });

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
