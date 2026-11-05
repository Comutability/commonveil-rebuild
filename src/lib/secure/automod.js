// AutoMod for an end-to-end encrypted server. The service can't read messages, so it can't filter
// them: the rules are an encrypted server item, and members' apps apply them. The sender's app
// won't send a message that breaks them, and every other member's app hides one that does (in case
// someone's app was changed to ignore the rules). Staff who can manage messages are exempt.

export const AUTOMOD_LIMITS = Object.freeze({ words: 200, wordChars: 60 });
export const MENTION_LIMITS = Object.freeze([0, 3, 5, 10, 20]);

export const EMPTY_AUTOMOD = Object.freeze({ enabled: false, words: [], block_links: false, block_invites: false, mention_limit: 0 });

export function cleanAutomod(payload) {
  if (!payload || typeof payload !== "object") return { ...EMPTY_AUTOMOD };
  const words = Array.isArray(payload.words)
    ? [...new Set(payload.words.filter((w) => typeof w === "string").map((w) => w.trim().toLowerCase()).filter((w) => w.replace(/\*/g, "").length >= 2))].slice(0, AUTOMOD_LIMITS.words).map((w) => w.slice(0, AUTOMOD_LIMITS.wordChars))
    : [];
  return {
    enabled: payload.enabled === true,
    words,
    block_links: payload.block_links === true,
    block_invites: payload.block_invites === true,
    mention_limit: MENTION_LIMITS.includes(payload.mention_limit) ? payload.mention_limit : 0,
  };
}

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** A word list entry as a pattern: whole words, with * standing for any letters. */
function wordPattern(w) {
  const body = w.split("*").map(escape).join("[\\p{L}\\p{N}]*");
  return new RegExp(`(^|[^\\p{L}\\p{N}])${body}($|[^\\p{L}\\p{N}])`, "iu");
}

const cache = new WeakMap();
function compiled(rules) {
  if (!cache.has(rules)) cache.set(rules, rules.words.map(wordPattern));
  return cache.get(rules);
}

const LINK_RE = /\bhttps?:\/\/|\bwww\.[a-z0-9-]+\.[a-z]/i;
const INVITE_RE = /\b(?:discord(?:app)?\.(?:gg|com\/invite)|commonveil\.[a-z]+\/(?:i|invite|join))\//i;

/**
 * Why AutoMod stops this message, in words for people, or null if it doesn't.
 * mentions: { users, roles, everyone } as sent with the message.
 */
export function automodReason(rules, text, mentions = null) {
  if (!rules?.enabled) return null;
  const t = String(text || "");
  if (rules.words.length && compiled(rules).some((re) => re.test(t))) return "It uses a word this server's AutoMod blocks.";
  if (rules.block_invites && INVITE_RE.test(t)) return "Invites to other servers aren't allowed here.";
  if (rules.block_links && LINK_RE.test(t)) return "Links aren't allowed here.";
  if (rules.mention_limit && mentions) {
    const n = (mentions.users?.length || 0) + (mentions.roles?.length || 0) + (mentions.everyone ? 1 : 0);
    if (n > rules.mention_limit) return `Messages here can mention up to ${rules.mention_limit} people or roles.`;
  }
  return null;
}
