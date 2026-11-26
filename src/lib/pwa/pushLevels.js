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

const RANK = { none: 0, mentions: 1, all: 2 };
const louder = (a, b) => ((RANK[b] ?? 0) > (RANK[a] ?? 0) ? b : a);

/** As many servers as the site accepts in one choice. */
export const MAX_ALERT_SERVERS = 1000;

/** { channels: [{ id, level }], all: [server ids], mentions: [server ids] }, from the app's servers and prefs. */
export function pushLevelsFor(servers, prefs) {
  const entries = Object.entries(servers || {});
  // A channel setting the app can't place yet (its server's channels haven't loaded) might belong to
  // any server still loading: those servers ask for at least that much, so nothing wanted is held back.
  const placed = new Set(entries.flatMap(([sid, entry]) => [sid, ...(entry?.channels || []).map((c) => c.id)]));
  const unplaced = Object.entries(prefs?.notify || {}).filter(([id]) => !placed.has(id)).reduce((acc, [, level]) => louder(acc, level), "none");
  const channels = [];
  const all = [];
  const mentions = [];
  for (const [sid, entry] of entries) {
    const list = (entry?.channels || []).filter((c) => PUSH_CHANNEL_KINDS.includes(c.kind));
    const levels = list.length ? list.map((c) => levelOf(prefs, sid, entry, c.id)) : [levelOf(prefs, sid, entry, null)];
    if (!list.length && !prefs?.muted?.[sid]) levels.push(unplaced);
    list.forEach((c, i) => channels.push({ id: c.id, level: levels[i] }));
    // Only servers the list has loaded are said to the site.
    if (!entry?.server) continue;
    if (levels.includes("all")) all.push(sid);
    else if (levels.includes("mentions")) mentions.push(sid);
  }
  all.sort();
  mentions.sort();
  return { channels, all: all.slice(0, MAX_ALERT_SERVERS), mentions: mentions.slice(0, Math.max(0, MAX_ALERT_SERVERS - all.length)) };
}
