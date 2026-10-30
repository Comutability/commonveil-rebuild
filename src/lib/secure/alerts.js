// Alerts on this device only: a browser notification while Commonveil is open in a tab, and
// an unread count in the tab's title. Both are off until turned on in Settings. Nothing about
// them is sent anywhere, and a notification never contains what a message says: at most who
// it's from, and only if that's switched on too.

export const DEFAULT_ALERTS = Object.freeze({ notify: false, showSender: false, titleCount: false });

/** Only the known switches, as booleans. */
export function cleanAlerts(value) {
  const v = value && typeof value === "object" ? value : {};
  return { notify: v.notify === true, showSender: v.showSender === true, titleCount: v.titleCount === true };
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
