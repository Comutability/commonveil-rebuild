// Server roles and permissions. src/lib/secure/permissions.js is a copy for the app (a test
// checks the two agree). The server enforces these; the app only uses them to decide what to show.
//
// Like Discord: a member's permissions are the union of @everyone's and their roles'. Channel
// overwrites then apply: @everyone's deny and allow, then the union of their roles' denies and
// allows. The owner, and anyone with ADMINISTRATOR, can do everything everywhere.

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

/** What @everyone can do in a new server. */
export const DEFAULT_EVERYONE =
  P.VIEW_CHANNEL | P.SEND_MESSAGES | P.ADD_REACTIONS | P.CREATE_POSTS | P.CONNECT | P.SPEAK | P.CREATE_INVITES | P.CHANGE_NICKNAME | P.READ_HISTORY;

/** Permissions that make someone staff: always shown in member lists, and counted as a moderator. */
export const STAFF_PERMISSIONS =
  P.ADMINISTRATOR | P.MANAGE_SERVER | P.MANAGE_ROLES | P.MANAGE_CHANNELS | P.MANAGE_MESSAGES | P.KICK_MEMBERS | P.BAN_MEMBERS | P.TIMEOUT_MEMBERS | P.MANAGE_TICKETS;

/** Permissions that only make sense server-wide; they're ignored in channel overwrites. */
export const SERVER_ONLY =
  P.ADMINISTRATOR | P.MANAGE_SERVER | P.MANAGE_ROLES | P.KICK_MEMBERS | P.BAN_MEMBERS | P.TIMEOUT_MEMBERS | P.VIEW_AUDIT_LOG |
  P.MANAGE_NICKNAMES | P.CHANGE_NICKNAME | P.MANAGE_KEYS | P.MANAGE_INVITES | P.MANAGE_EXPRESSIONS | P.MANAGE_EVENTS;

const toInt = (v: unknown) => (Number.isInteger(v) ? (v as number) & ALL_PERMISSIONS : 0);

/** Roles by id, the @everyone role, and the member's own roles, highest first. */
function rolesOf(roles: any[], member: any) {
  const everyone = roles.find((r) => r.is_everyone) || null;
  const ids = new Set<string>(member?.role_ids || []);
  const mine = roles.filter((r) => !r.is_everyone && ids.has(r.id)).sort((a, b) => (b.position || 0) - (a.position || 0));
  return { everyone, mine };
}

/** Server-wide permissions for a member. */
export function basePermissions(server: any, roles: any[], member: any): number {
  if (!member) return 0;
  if (server?.owner_id && member.user_id === server.owner_id) return ALL_PERMISSIONS;
  const { everyone, mine } = rolesOf(roles, member);
  let perms = toInt(everyone?.permissions);
  for (const r of mine) perms |= toInt(r.permissions);
  if (perms & P.ADMINISTRATOR) return ALL_PERMISSIONS;
  return perms;
}

/** A member's permissions in one channel, after its overwrites. */
export function channelPermissions(server: any, roles: any[], member: any, channel: any): number {
  const base = basePermissions(server, roles, member);
  if (!member || base === ALL_PERMISSIONS) return base;
  const { everyone, mine } = rolesOf(roles, member);
  const overwrites: any[] = Array.isArray(channel?.overwrites) ? channel.overwrites : [];
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
  // Without seeing a channel, nothing else in it applies.
  if (!(perms & P.VIEW_CHANNEL)) return 0;
  return perms;
}

export const has = (perms: number, bit: number) => (perms & bit) === bit;

/** The highest position among a member's roles (the owner is above everyone). */
export function topPosition(server: any, roles: any[], member: any): number {
  if (!member) return -1;
  if (server?.owner_id && member.user_id === server.owner_id) return Number.MAX_SAFE_INTEGER;
  const { mine } = rolesOf(roles, member);
  return mine.length ? mine[0].position || 0 : 0;
}

/** True if this member counts as staff in this server. */
export function isStaff(server: any, roles: any[], member: any): boolean {
  return (basePermissions(server, roles, member) & STAFF_PERMISSIONS) !== 0;
}

/**
 * A channel is private when not everyone can see it: @everyone can't (an overwrite denies
 * VIEW_CHANNEL, or @everyone doesn't have it), or some role is denied it. Private channels get
 * their own key chain, given only to those who can see them, so a deny really hides messages.
 */
export function channelIsPrivate(roles: any[], channel: any): boolean {
  if (channel?.kind === "category") return false;
  const everyone = roles.find((r) => r.is_everyone);
  if (!everyone) return true;
  let perms = toInt(everyone.permissions);
  if (perms & P.ADMINISTRATOR) return false;
  const ev = (Array.isArray(channel?.overwrites) ? channel.overwrites : []).find((o: any) => o.role_id === everyone.id);
  if (ev) perms = (perms & ~toInt(ev.deny)) | toInt(ev.allow);
  if (!(perms & P.VIEW_CHANNEL)) return true;
  return (Array.isArray(channel?.overwrites) ? channel.overwrites : []).some((o: any) => o.role_id !== everyone.id && (toInt(o.deny) & P.VIEW_CHANNEL) !== 0);
}
