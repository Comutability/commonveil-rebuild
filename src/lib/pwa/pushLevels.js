// Push levels from this device's own notification settings ("all", "mentions" or "none"):
// - per channel, for the service worker, which decides what a push that arrives may show;
// - per server, for the site (notifications `alerts`), which pushes a server's activity only to
//   browsers that asked for it. A server's most talkative channel decides, so nothing the person
//   wants is held back, and the worker still quietens the rest. The site never learns a channel's.

/** The channels that can push. */
export const PUSH_CHANNEL_KINDS = ["text", "announcement", "rules", "forum"];

/** One channel's level (channelId null: the server's own setting, for channels not loaded yet). */
export function levelOf(prefs, sid, entry, channelId) {
  if (prefs?.muted?.[sid] || (channelId && prefs?.muted?.[channelId])) return "none";
  return (channelId && prefs?.notify?.[channelId]) || prefs?.notify?.[sid] || (entry?.server?.is_default ? "mentions" : "all");
}

/** { channels: [{ id, level }], all: [server ids], mentions: [server ids] }, from the app's servers and prefs. */
export function pushLevelsFor(servers, prefs) {
  const channels = [];
  const all = [];
  const mentions = [];
  for (const [sid, entry] of Object.entries(servers || {})) {
    const list = (entry?.channels || []).filter((c) => PUSH_CHANNEL_KINDS.includes(c.kind));
    const levels = list.length ? list.map((c) => levelOf(prefs, sid, entry, c.id)) : [levelOf(prefs, sid, entry, null)];
    list.forEach((c, i) => channels.push({ id: c.id, level: levels[i] }));
    // Only servers the list has loaded are said to the site.
    if (!entry?.server) continue;
    if (levels.includes("all")) all.push(sid);
    else if (levels.includes("mentions")) mentions.push(sid);
  }
  return { channels, all: all.sort(), mentions: mentions.sort() };
}
