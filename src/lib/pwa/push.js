// Push notifications on this device (docs/NOTIFICATIONS.md). They say only "New message" or "New
// activity", even to this device; tapping one opens the app, which asks where to go.
import { callFn } from "@/lib/api";
import { workerUrl } from "@/lib/pwa/app";
import { pushHint } from "@/lib/pwa/browser";
import { muteToken } from "@/lib/pwa/mute";
import { pushLevelsFor } from "@/lib/pwa/pushLevels";
import { serialise } from "@/lib/pwa/serial";

const supported = () => typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
const KEY = "commonveil_push_secret";
// A phone can take a moment to start the service worker behind the app: long enough for a slow
// connection, short enough that a worker which never starts says so instead of spinning forever.
const SW_WAIT_MS = 12_000;
// Whether this visit has already told the site which browser this is.
let told = false;
// Which servers this browser wants pushes from, as last worked out (mirrorServerPushPrefs), and what
// this visit last told the site, so the same choice isn't sent twice.
let alertChoice = null;
let alertsSaid = "";
let alertsTimer = null;
const ALERTS_SETTLE_MS = 1500;
// One alerts request at a time; a choice made while one is on its way goes after it (serialise).
let alertsRetry = false;
const ALERTS_RETRY_MS = 60_000;
// Each mirror call's turn: an older one finishing late mustn't overwrite a newer one's work.
let mirrorTurn = 0;

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
  // A new subscription starts without a choice of servers: say it again, if it's known yet.
  alertsSaid = "";
  if (alertChoice) sayAlerts().catch(() => {});
}

/**
 * Tell the site which servers this browser wants pushes from: every server, never a channel. The
 * site sends a server's pushes only to browsers that asked for them, and this browser still
 * applies each channel's own setting to what arrives (public/sw.js).
 */
const sayAlerts = serialise(sayAlertsOnce);

async function sayAlertsOnce() {
  if (!alertChoice || !supported()) return;
  const reg = await navigator.serviceWorker.getRegistration("/").catch(() => null);
  const sub = await reg?.pushManager.getSubscription().catch(() => null);
  // No push on this browser: there's nothing to choose.
  if (!sub) return;
  const choice = alertChoice;
  const said = JSON.stringify({ endpoint: sub.endpoint, ...choice });
  if (said === alertsSaid) return;
  try {
    await callFn("notifications", { action: "alerts", endpoint: sub.endpoint, all: choice.all, mentions: choice.mentions });
    alertsSaid = said;
  } catch (err) {
    // Offline, or the site was busy: say it again once the connection is back, or in a minute.
    // A refusal (an unregistered browser, a bad list) waits for the next change instead.
    const status = Number(err?.status) || 0;
    if (status === 0 || status === 429 || status >= 500) retryAlerts();
    throw err;
  }
}

function retryAlerts() {
  if (alertsRetry || typeof window === "undefined") return;
  alertsRetry = true;
  const again = () => {
    alertsRetry = false;
    sayAlerts().catch(() => {});
  };
  if (navigator.onLine === false) window.addEventListener("online", again, { once: true });
  else setTimeout(again, ALERTS_RETRY_MS);
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
 * Send the site's test push and watch this device for it. Answers { state }:
 *   "shown"    the notification is on this device: it works;
 *   "received" the push reached Commonveil here, but the phone didn't show it (its own settings
 *              for this browser are off: nothing a site can override);
 *   "blocked"  the push service accepted it for this device, and nothing arrived at all;
 *   "refused"  the push service turned the send down, so nothing went out;
 *   "unknown"  this browser can't be asked, so only the service's answer is known.
 * Both ends have a say: the service says whether it took the send, the worker says when it receives
 * a push, and the list of showing notifications says when one was actually displayed.
 */
export async function sendTestPush(waitMs = 12_000) {
  const reg = await registration().catch(() => null);
  if (!reg) return { state: "unavailable" };
  const look = async () => {
    try {
      return await reg.getNotifications({ tag: "commonveil-test" });
    } catch {
      return null;
    }
  };
  let received = false;
  const answer = (state, sent, details = {}) => ({ state, sent, ...details });
  const heard = (event) => {
    if (event.data?.type === "push-received") received = true;
  };
  navigator.serviceWorker.addEventListener("message", heard);
  try {
    // Clear any earlier one, so only something new counts as an arrival.
    for (const old of (await look()) || []) old.close();
    const sub = await reg.pushManager.getSubscription();
    if (!sub) throw new Error("This browser is not subscribed. Turn push off and on again.");
    const reply = await callFn("notifications", { action: "test", endpoint: sub.endpoint });
    const sent = Number(reply?.sent) || 0;
    const details = {
      status: Number(reply?.status_code) || null,
      reason: reply?.failure_reason || (reply?.rejected ? "http_rejected" : reply?.failed ? "internal_error" : reply?.gone ? "expired" : "no_attempt"),
      attempted: Number(reply?.attempted) || 0,
      category: typeof reply?.error_category === "string" ? reply.error_category : null,
      probe: reply?.fcm_probe || null,
    };
    // If the push failed before acceptance, the worker cannot receive it: report immediately.
    if (!sent) return answer("refused", sent, details);
    let countable = typeof reg.getNotifications === "function";
    const until = Date.now() + waitMs;
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, 500));
      if (countable) {
        const seen = await look();
        if (seen === null) countable = false;
        else if (seen.length) return answer("shown", sent);
      }
      if (received && !countable) return answer("received", sent);
    }
    if (received) return answer("received", sent);
    return answer(countable ? "blocked" : "unknown", sent, details);
  } finally {
    navigator.serviceWorker.removeEventListener("message", heard);
  }
}

/** Mirror quiet hours and focus for the service worker, which can't read the app's storage. */
/** Merge preferences in one transaction so message and channel settings cannot overwrite each other. */
function writeWorkerPrefs(changes) {
  if (typeof indexedDB === "undefined") return;
  try {
    const open = indexedDB.open("commonveil-push", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("kv");
    open.onsuccess = () => {
      try {
        const tx = open.result.transaction("kv", "readwrite");
        const store = tx.objectStore("kv");
        const read = store.get("prefs");
        read.onsuccess = () => store.put({ ...(read.result || {}), ...changes }, "prefs");
      } catch { /* No worker preferences to update. */ }
    };
  } catch { /* IndexedDB is unavailable. */ }
}

/** Mirror quiet hours and focus without erasing channel-specific choices. */
export function mirrorPushPrefs(alerts) {
  writeWorkerPrefs({ quiet: alerts.quiet, quietFrom: alerts.quietFrom, quietTo: alerts.quietTo, focusUntil: alerts.focusUntil });
}

/**
 * Each channel's push level for the service worker, keyed by the same per-device HMAC the site
 * puts in a push (so no channel id is stored for it). Once the server list has loaded, the site is
 * told per server only (sayAlerts; lib/pwa/pushLevels.js says how).
 */
export async function mirrorServerPushPrefs(servers, prefs, loaded = false) {
  if (!supported() || !crypto?.subtle) return;
  const turn = ++mirrorTurn;
  const secret = muteSecret();
  const { channels, all, mentions } = pushLevelsFor(servers, prefs);
  const pushLevels = {};
  for (const c of channels) pushLevels[await muteToken(secret, c.id)] = c.level;
  // A newer call started while this one worked: its answer is the one that counts.
  if (turn !== mirrorTurn) return;
  writeWorkerPrefs({ pushLevels });
  if (!loaded) return;
  // A server list still filling in changes this several times in a row: say only where it settles.
  alertChoice = { all, mentions };
  clearTimeout(alertsTimer);
  alertsTimer = setTimeout(() => sayAlerts().catch(() => {}), ALERTS_SETTLE_MS);
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