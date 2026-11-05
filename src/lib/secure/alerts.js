// Alerts on this device only: a browser notification while Commonveil is open in a tab, and
// an unread count in the tab's title. Both are off until turned on in Settings. Nothing about
// them is sent anywhere, and a notification never contains what a message says: at most who
// it's from, and only if that's switched on too.

// Quiet hours and focus are kept here too, on this device only: the service never learns when
// you sleep or when you don't want to be disturbed.
export const DEFAULT_ALERTS = Object.freeze({
  notify: false, showSender: false, titleCount: false,
  quiet: false, quietFrom: 22 * 60, quietTo: 7 * 60, focusUntil: 0,
});

const minuteOfDay = (v, fallback) => (Number.isInteger(v) && v >= 0 && v < 24 * 60 ? v : fallback);

/** Only the known switches, as booleans, and quiet-hours times as minutes past midnight. */
export function cleanAlerts(value) {
  const v = value && typeof value === "object" ? value : {};
  const focus = Number(v.focusUntil);
  return {
    notify: v.notify === true,
    showSender: v.showSender === true,
    titleCount: v.titleCount === true,
    quiet: v.quiet === true,
    quietFrom: minuteOfDay(v.quietFrom, DEFAULT_ALERTS.quietFrom),
    quietTo: minuteOfDay(v.quietTo, DEFAULT_ALERTS.quietTo),
    // Focus lasts at most a day; anything else is dropped.
    focusUntil: Number.isFinite(focus) && focus > 0 && focus < Date.now() + 25 * 3600_000 ? Math.floor(focus) : 0,
  };
}

/** Whether notifications should stay silent right now: focus is on, or it's within quiet hours. */
export function isQuiet(settings, now = new Date()) {
  if (!settings) return false;
  if (settings.focusUntil && now.getTime() < settings.focusUntil) return true;
  if (!settings.quiet || settings.quietFrom === settings.quietTo) return false;
  const m = now.getHours() * 60 + now.getMinutes();
  const { quietFrom: a, quietTo: b } = settings;
  return a < b ? m >= a && m < b : m >= a || m < b;
}

/** "22:00" ⇄ 1320. */
export const minutesToTime = (m) => `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
export function timeToMinutes(s) {
  const match = /^(\d{1,2}):(\d{2})$/.exec(String(s || ""));
  if (!match) return null;
  const h = Number(match[1]);
  const min = Number(match[2]);
  return h < 24 && min < 60 ? h * 60 + min : null;
}

export const notificationsSupported = () => typeof window !== "undefined" && "Notification" in window;

/** "granted", "denied", "default" (not asked yet) or "unsupported". */
export const notificationPermission = () => (notificationsSupported() ? window.Notification.permission : "unsupported");

export async function askNotificationPermission() {
  if (!notificationsSupported()) return "unsupported";
  try {
    return await window.Notification.requestPermission();
  } catch {
    return window.Notification.permission;
  }
}

/** The words a notification uses. The message itself is never included. */
export function alertText(settings, senderName) {
  return settings.showSender && senderName ? `New message from ${senderName}` : "New message";
}

/** Show one notification. Messages in the same conversation replace each other rather than pile up. */
export function showAlert({ body, tag, onClick }) {
  if (notificationPermission() !== "granted") return false;
  try {
    const n = new window.Notification("Commonveil", { body, tag });
    n.onclick = () => {
      window.focus();
      onClick?.();
      n.close();
    };
    return true;
  } catch {
    // Some mobile browsers only show notifications from a service worker, which this site doesn't use.
    return false;
  }
}
