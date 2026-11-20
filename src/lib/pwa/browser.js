// Which browser this is, and the one thing it needs before a push can arrive
// (docs/NOTIFICATIONS.md). Web push works in Chrome, Firefox, Brave and Safari on a phone; what
// differs is the switch each of them keeps outside the site, where a page can't reach it.

export function browserName() {
  if (typeof navigator === "undefined") return "";
  // Brave is Chrome underneath: only this object tells them apart.
  if (navigator.brave) return "brave";
  const ua = navigator.userAgent || "";
  if (/Firefox|FxiOS/i.test(ua)) return "firefox";
  if (/Edg\//.test(ua)) return "edge";
  if (/OPR\//.test(ua)) return "opera";
  if (/Chrome|CriOS/i.test(ua)) return "chrome";
  if (/Safari/i.test(ua)) return "safari";
  return "";
}

/** The one switch to look for in this browser when a push doesn't arrive. */
export function pushHint() {
  switch (browserName()) {
    case "brave":
      return "In Brave, open Settings → Privacy and security and turn on “Use Google services for push messaging”. Brave sends no notifications at all while that is off, even though the site says they're on.";
    case "firefox":
      return "In Firefox, allow notifications for this site (the padlock in the address bar → Permissions), and let Firefox post notifications in your phone's settings.";
    case "chrome":
    case "edge":
    case "opera":
      return "Allow notifications for this site (the padlock in the address bar → Permissions), and let Chrome post notifications in your phone's settings. Android 13 and later asks per app.";
    case "safari":
      return "In Safari on iPhone or iPad, Commonveil has to be on your Home Screen, with notifications allowed in Settings → Notifications.";
    default:
      return "Allow notifications for this site in your browser, and let the browser post them in your phone's settings.";
  }
}