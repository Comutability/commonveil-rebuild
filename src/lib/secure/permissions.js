// Copy of base44/shared/permissions.ts for the app; tests/servers.test.mjs checks they agree.
// The server enforces permissions. The app uses these only to decide what to show.

export const P = Object.freeze({
  VIEW_CHANNEL: 1 << 0,
  SEND_MESSAGES: 1 << 1,
  ADD_REACTIONS: 1 << 2,
  CREATE_POSTS: 1 << 3,
  CONNECT: 1 << 4,
  SPEAK: 1 << 5,
  MENTION_EVERYONE: 1 << 6,
  MANAGE_MESSAGES: 1 << 7,
  MANAGE_CHANNELS: 1 << 8,
  MANAGE_ROLES: 1 << 9,
  MANAGE_SERVER: 1 << 10,
  CREATE_INVITES: 1 << 11,
  MANAGE_INVITES: 1 << 12,
  KICK_MEMBERS: 1 << 13,
  BAN_MEMBERS: 1 << 14,
  TIMEOUT_MEMBERS: 1 << 15,
  VIEW_AUDIT_LOG: 1 << 16,
  MANAGE_TICKETS: 1 << 17,
  MANAGE_NICKNAMES: 1 << 18,
  CHANGE_NICKNAME: 1 << 19,
  MANAGE_KEYS: 1 << 20,
  READ_HISTORY: 1 << 21,
  MANAGE_EXPRESSIONS: 1 << 22,
  MANAGE_EVENTS: 1 << 23,
  MUTE_MEMBERS: 1 << 24,
  MANAGE_THREADS: 1 << 25,
  ADMINISTRATOR: 1 << 30,
});

export const ALL_PERMISSIONS = Object.values(P).reduce((a, b) => a | b, 0);

export const DEFAULT_EVERYONE =
  P.VIEW_CHANNEL | P.SEND_MESSAGES | P.ADD_REACTIONS | P.CREATE_POSTS | P.CONNECT | P.SPEAK | P.CREATE_INVITES | P.CHANGE_NICKNAME | P.READ_HISTORY;

export const STAFF_PERMISSIONS =
  P.ADMINISTRATOR | P.MANAGE_SERVER | P.MANAGE_ROLES | P.MANAGE_CHANNELS | P.MANAGE_MESSAGES | P.KICK_MEMBERS | P.BAN_MEMBERS | P.TIMEOUT_MEMBERS | P.MANAGE_TICKETS;

export const SERVER_ONLY =
  P.ADMINISTRATOR | P.MANAGE_SERVER | P.MANAGE_ROLES | P.KICK_MEMBERS | P.BAN_MEMBERS | P.TIMEOUT_MEMBERS | P.VIEW_AUDIT_LOG |
  P.MANAGE_NICKNAMES | P.CHANGE_NICKNAME | P.MANAGE_KEYS | P.MANAGE_INVITES | P.MANAGE_EXPRESSIONS | P.MANAGE_EVENTS;

/** Labels and groups for the role editor, in the order they're shown. */
export const PERMISSION_INFO = Object.freeze([
  { group: "General", bit: P.VIEW_CHANNEL, label: "View channels", help: "See channels and read what's in them." },
  { group: "General", bit: P.MANAGE_CHANNELS, label: "Manage channels", help: "Create, edit, reorder and delete channels." },
  { group: "General", bit: P.MANAGE_ROLES, label: "Manage roles", help: "Create and edit roles below their own, and give them to members." },
  { group: "General", bit: P.MANAGE_SERVER, label: "Manage server", help: "Change the server's name, settings, rules and discovery listing." },
  { group: "General", bit: P.VIEW_AUDIT_LOG, label: "View audit log", help: "See who changed what in the server's settings." },
  { group: "General", bit: P.MANAGE_EXPRESSIONS, label: "Manage emoji and stickers", help: "Add, rename and remove the server's own emoji and stickers." },
  { group: "General", bit: P.MANAGE_EVENTS, label: "Manage events", help: "Schedule, edit and cancel the server's events." },
  { group: "General", bit: P.MANAGE_KEYS, label: "Manage encryption", help: "Start new key generations, so people who left can't read what comes next." },
  { group: "Membership", bit: P.CREATE_INVITES, label: "Create invites", help: "Make invite links." },
  { group: "Membership", bit: P.MANAGE_INVITES, label: "Manage invites", help: "See and revoke everyone's invite links." },
  { group: "Membership", bit: P.CHANGE_NICKNAME, label: "Change nickname", help: "Set their own nickname in this server." },
  { group: "Membership", bit: P.MANAGE_NICKNAMES, label: "Manage nicknames", help: "Change other members' nicknames." },
  { group: "Membership", bit: P.KICK_MEMBERS, label: "Kick members", help: "Remove members. They can come back with an invite." },
  { group: "Membership", bit: P.BAN_MEMBERS, label: "Ban members", help: "Remove members for good. Keys are renewed so they can't read anything new." },
  { group: "Membership", bit: P.TIMEOUT_MEMBERS, label: "Time out members", help: "Stop members posting or joining calls for a while." },
  { group: "Text", bit: P.SEND_MESSAGES, label: "Send messages", help: "Post in text channels and reply in forum posts." },
  { group: "Text", bit: P.CREATE_POSTS, label: "Create forum posts", help: "Start new posts in forum channels." },
  { group: "Text", bit: P.ADD_REACTIONS, label: "Add reactions", help: "React to messages." },
  { group: "Text", bit: P.READ_HISTORY, label: "Read message history", help: "Page back through earlier messages." },
  { group: "Text", bit: P.MENTION_EVERYONE, label: "Mention @everyone", help: "Notify everyone in a channel at once." },
  { group: "Text", bit: P.MANAGE_THREADS, label: "Manage threads", help: "Rename, archive, lock and delete anyone's threads." },
  { group: "Text", bit: P.MANAGE_MESSAGES, label: "Manage messages", help: "Delete anyone's messages and pin messages." },
  { group: "Support", bit: P.MANAGE_TICKETS, label: "Handle support tickets", help: "Receive and answer the server's support tickets." },
  { group: "Voice", bit: P.CONNECT, label: "Connect", help: "Join voice channels." },
  { group: "Voice", bit: P.SPEAK, label: "Speak", help: "Talk in voice channels." },
  { group: "Voice", bit: P.MUTE_MEMBERS, label: "Mute members and run stages", help: "Mute people in calls, and invite or move speakers on a stage." },
  { group: "Advanced", bit: P.ADMINISTRATOR, label: "Administrator", help: "Every permission, in every channel. Give it carefully." },
]);

const toInt = (v) => (Number.isInteger(v) ? v & ALL_PERMISSIONS : 0);

function rolesOf(roles, member) {
  const everyone = roles.find((r) => r.is_everyone) || null;
  const ids = new Set(member?.role_ids || []);
  const mine = roles.filter((r) => !r.is_everyone && ids.has(r.id)).sort((a, b) => (b.position || 0) - (a.position || 0));
  return { everyone, mine };
}

export function basePermissions(server, roles, member) {
  if (!member) return 0;
  if (server?.owner_id && member.user_id === server.owner_id) return ALL_PERMISSIONS;
  const { everyone, mine } = rolesOf(roles, member);
  let perms = toInt(everyone?.permissions);
  for (const r of mine) perms |= toInt(r.permissions);
  if (perms & P.ADMINISTRATOR) return ALL_PERMISSIONS;
  return perms;
}

export function channelPermissions(server, roles, member, channel) {
  const base = basePermissions(server, roles, member);
  if (!member || base === ALL_PERMISSIONS) return base;
  const { everyone, mine } = rolesOf(roles, member);
  const overwrites = Array.isArray(channel?.overwrites) ? channel.overwrites : [];
  const channelBits = ALL_PERMISSIONS & ~SERVER_ONLY;
  let perms = base;
  const ev = everyone ? overwrites.find((o) => o.role_id === everyone.id) : null;
  if (ev) perms = (perms & ~(toInt(ev.deny) & channelBits)) | (toInt(ev.allow) & channelBits);
  let allow = 0;
  let deny = 0;
  const myIds = new Set(mine.map((r) => r.id));
  for (const o of overwrites) {
    if (!myIds.has(o.role_id)) continue;
    allow |= toInt(o.allow);
    deny |= toInt(o.deny);
  }
  perms = (perms & ~(deny & channelBits)) | (allow & channelBits);
  if (!(perms & P.VIEW_CHANNEL)) return 0;
  return perms;
}

export const has = (perms, bit) => (perms & bit) === bit;

export function topPosition(server, roles, member) {
  if (!member) return -1;
  if (server?.owner_id && member.user_id === server.owner_id) return Number.MAX_SAFE_INTEGER;
  const { mine } = rolesOf(roles, member);
  return mine.length ? mine[0].position || 0 : 0;
}

export function isStaff(server, roles, member) {
  return (basePermissions(server, roles, member) & STAFF_PERMISSIONS) !== 0;
}

export function channelIsPrivate(roles, channel) {
  if (channel?.kind === "category") return false;
  const everyone = roles.find((r) => r.is_everyone);
  if (!everyone) return true;
  let perms = toInt(everyone.permissions);
  if (perms & P.ADMINISTRATOR) return false;
  const ev = (Array.isArray(channel?.overwrites) ? channel.overwrites : []).find((o) => o.role_id === everyone.id);
  if (ev) perms = (perms & ~toInt(ev.deny)) | toInt(ev.allow);
  if (!(perms & P.VIEW_CHANNEL)) return true;
  return (Array.isArray(channel?.overwrites) ? channel.overwrites : []).some((o) => o.role_id !== everyone.id && (toInt(o.deny) & P.VIEW_CHANNEL) !== 0);
}
