// Making a server from a template, joining one, and taking someone out of one.
import { ApiError } from "../http.ts";
import { P, channelIsPrivate, channelPermissions, has } from "../permissions.ts";
import { byAge, withRow } from "../store.ts";
import { COMMUNITY, type Template } from "./template.ts";
import {
  SERVER_LIMITS,
  channelChainId,
  historyChainId,
  liveChainId,
  memberRow,
  needRotation,
  refreshAccess,
  serverParts,
  visiblePrivate,
} from "./model.ts";

/** The community server's public card (it's listed in Discover). */
export const COMMUNITY_PUBLIC = Object.freeze({
  public_name: "Commonveil Community",
  public_description: "Help, guides, ideas and good company from the people behind Commonveil and everyone using it. Everything here is end-to-end encrypted.",
  public_tags: ["privacy", "security", "support", "community", "learning"],
  public_icon: "CV",
  public_color: "#0f766e",
});

/** Create a server with a template's roles, categories and channels. */
export async function createFromTemplate(sr: any, template: Template, { ownerId, isDefault, now }: { ownerId: string; isDefault: boolean; now: Date }) {
  const server = await sr.entities.Server.create({
    owner_id: ownerId,
    audience_id: "pending",
    is_default: isDefault,
    template: template.key,
    join_mode: isDefault ? "open" : "invite",
    discoverable: isDefault,
    ...(isDefault ? COMMUNITY_PUBLIC : {}),
    rules_required: isDefault,
    min_account_minutes: 0,
    min_member_minutes: 0,
    invites_paused: false,
    joins_paused: false,
    member_list: "opt_in",
    audit_retention_days: 90,
    default_history: "joined",
    allow_member_dms: true,
    // In the community server only staff hand out keys, so ordinary members never learn who joins.
    key_handout: isDefault ? "staff" : "members",
    member_count: 0,
    status: "active",
    changed_at: now.toISOString(),
  });
  await sr.entities.Server.update(server.id, { audience_id: server.id });
  server.audience_id = server.id;

  const roleIds: Record<string, string> = {};
  const roles: any[] = [];
  const everyone = await sr.entities.Role.create({
    server_id: server.id, audience_id: server.id, position: 0, permissions: template.everyone, is_everyone: true, template_key: "everyone", hoist: false, mentionable: false,
  });
  roleIds.everyone = everyone.id;
  roles.push(everyone);
  for (const r of template.roles) {
    const row = await sr.entities.Role.create({
      server_id: server.id, audience_id: server.id, position: r.position, permissions: r.permissions, is_everyone: false, template_key: r.key, hoist: r.hoist, mentionable: r.mentionable,
    });
    roleIds[r.key] = row.id;
    roles.push(row);
  }

  const channelIds: Record<string, string> = {};
  let position = 0;
  const chains = [
    { server_id: server.id, audience_id: server.id, chain_id: historyChainId(server.id), kind: "h", channel_id: "", rotation_needed: false },
    { server_id: server.id, audience_id: server.id, chain_id: liveChainId(server.id), kind: "l", channel_id: "", rotation_needed: false },
  ];
  for (const c of template.channels) {
    const overwrites = (c.overwrites || [])
      .map((o) => ({ role_id: roleIds[o.role], allow: o.allow || 0, deny: o.deny || 0 }))
      .filter((o) => o.role_id);
    const isPrivate = channelIsPrivate(roles, { kind: c.kind, overwrites });
    const row = await sr.entities.Channel.create({
      server_id: server.id,
      audience_id: server.id,
      kind: c.kind,
      parent_id: c.parent ? channelIds[c.parent] || "" : "",
      position: position++,
      template_key: c.key,
      history: c.history || "joined",
      private: isPrivate,
      overwrites,
      slowmode_seconds: c.slowmode || 0,
      expire_seconds: 0,
      sensitive: false,
      creator_id: ownerId,
    });
    channelIds[c.key] = row.id;
    if (isPrivate) {
      await sr.entities.Channel.update(row.id, { audience_id: row.id });
      chains.push({ server_id: server.id, audience_id: row.id, chain_id: channelChainId(server.id, row.id), kind: "c", channel_id: row.id, rotation_needed: false });
    }
  }
  await sr.entities.KeyChain.bulkCreate(chains);
  return server;
}

/** The community server: made the first time anyone needs it. Two at once: the older one stays. */
export async function ensureDefaultServer(sr: any, now: Date) {
  const existing = (await sr.entities.Server.filter({ is_default: true }, "created_date", 5)).filter((s: any) => s.status !== "deleting").sort(byAge);
  if (existing.length) return existing[0];
  const made = await createFromTemplate(sr, COMMUNITY, { ownerId: "", isDefault: true, now });
  const all = withRow((await sr.entities.Server.filter({ is_default: true }, "created_date", 5)).filter((s: any) => s.status !== "deleting"), made);
  if (all[0].id !== made.id) {
    await sr.entities.Server.update(made.id, { status: "deleting", is_default: false });
    return all[0];
  }
  return made;
}

/** The email addresses that become the community server's admins, the first its owner. */
export function cleanAdminList(list: unknown): string[] {
  const raw = Array.isArray(list) ? list : String(list || "").split(",");
  return raw.map((e) => String(e || "").trim().toLowerCase()).filter((e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)).slice(0, 10);
}

/**
 * Add someone to a server. Checks bans, pauses and limits; the caller has checked the way in
 * (an invite, an open server, the community server). Returns the member row.
 */
export async function addMember(sr: any, server: any, user: any, { listed = false, adminEmails = [] as string[], now }: any) {
  if (server.status === "deleting") throw new ApiError(404, "SERVER_NOT_FOUND", "Server not found.");
  const existing = await memberRow(sr, server.id, user.id);
  if (existing) return { member: existing, joined: false };
  if (server.joins_paused) throw new ApiError(403, "JOINS_PAUSED", "This server isn't taking new members at the moment.");
  const banned = await sr.entities.ServerBan.filter({ server_id: server.id, user_id: user.id }, "created_date", 1);
  if (banned.length) throw new ApiError(403, "BANNED", "You can't join this server.");
  if ((Number(server.member_count) || 0) >= SERVER_LIMITS.membersPerServer) throw new ApiError(409, "SERVER_FULL", "This server is full.");
  const mine = await sr.entities.ServerMember.filter({ user_id: user.id }, "created_date", SERVER_LIMITS.serversPerUser + 1);
  if (mine.length >= SERVER_LIMITS.serversPerUser) {
    throw new ApiError(409, "TOO_MANY_SERVERS", `You can be in up to ${SERVER_LIMITS.serversPerUser} servers. Leave one first.`);
  }

  const roleIds: string[] = [];
  let makeOwner = false;
  if (server.is_default && adminEmails.length && user.email) {
    const email = String(user.email).toLowerCase();
    if (adminEmails.includes(email)) {
      const [admin] = await sr.entities.Role.filter({ server_id: server.id, template_key: "admin" }, "created_date", 1);
      if (admin) roleIds.push(admin.id);
      if (!server.owner_id && email === adminEmails[0]) makeOwner = true;
    }
  }
  const created = await sr.entities.ServerMember.create({
    server_id: server.id,
    user_id: user.id,
    role_ids: roleIds,
    joined_at: now.toISOString(),
    listed: Boolean(listed) || roleIds.length > 0,
    rules_accepted_at: "",
    timeout_until: "",
    key_status: "pending",
  });
  // Two joins at once: one row stays.
  const rows = withRow(await sr.entities.ServerMember.filter({ server_id: server.id, user_id: user.id }, "created_date", 5), created);
  if (rows[0].id !== created.id) {
    await sr.entities.ServerMember.delete(created.id);
    return { member: rows[0], joined: false };
  }
  await sr.entities.Server.update(server.id, {
    member_count: (Number(server.member_count) || 0) + 1,
    keys_pending_at: now.toISOString(),
    ...(makeOwner ? { owner_id: user.id, changed_at: now.toISOString() } : {}),
  });
  await refreshAccess(sr, user.id);
  return { member: created, joined: true };
}

/**
 * Take someone out of a server (leaving, kicked, banned, or their account deleted). Their
 * copies of the server's keys go. If they could come back only by invitation (a private server,
 * or a ban), the keys they held are due a new generation.
 */
export async function removeMember(sr: any, serverId: string, userId: string, { reason, now }: { reason: "left" | "kicked" | "banned" | "deleted"; now: Date }) {
  const parts = await serverParts(sr, serverId);
  const member = await memberRow(sr, serverId, userId);
  if (!member) return false;
  const held = [historyChainId(serverId), liveChainId(serverId), ...visiblePrivate(parts, member).map((c: string) => channelChainId(serverId, c))];
  for (const row of await sr.entities.ServerMember.filter({ server_id: serverId, user_id: userId }, "created_date", 5)) {
    await sr.entities.ServerMember.delete(row.id);
  }
  await sr.entities.KeyGrant.deleteMany({ server_id: serverId, user_id: userId });
  await sr.entities.Server.update(parts.server.id, { member_count: Math.max(0, (Number(parts.server.member_count) || 1) - 1) });
  const rotate = reason === "banned" || parts.server.join_mode !== "open";
  if (rotate) await needRotation(sr, serverId, held, reason);
  await refreshAccess(sr, userId);
  return true;
}

/**
 * Members who can see a private channel: those with a role whose overwrite lets them in, or an
 * administrator role, and the owner. (@everyone can't, or it wouldn't be private.)
 */
export async function membersWhoCanSee(sr: any, parts: any, channel: any) {
  const overwriteRoles = (channel.overwrites || []).filter((o: any) => (Number(o.allow) & P.VIEW_CHANNEL) !== 0).map((o: any) => o.role_id);
  const adminRoles = parts.roles.filter((r: any) => !r.is_everyone && (Number(r.permissions) & P.ADMINISTRATOR) !== 0).map((r: any) => r.id);
  const roleIds = [...new Set([...overwriteRoles, ...adminRoles])];
  const found: any[] = [];
  if (roleIds.length) found.push(...(await sr.entities.ServerMember.filter({ server_id: parts.server.id, role_ids: { $in: roleIds } }, "joined_at", 5000)));
  if (parts.server.owner_id && !found.some((m) => m.user_id === parts.server.owner_id)) {
    const owner = await memberRow(sr, parts.server.id, parts.server.owner_id);
    if (owner) found.push(owner);
  }
  return found.filter((m: any) => has(channelPermissions(parts.server, parts.roles, m, channel), P.VIEW_CHANNEL));
}
