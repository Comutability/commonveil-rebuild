// Servers (communities): membership, keys, roles, channels, settings, moderation, invites,
// discovery and support tickets. Content is end-to-end encrypted on members' devices; this
// code stores ciphertext, enforces permissions and keeps track of who still needs which keys.
import { ApiError, LIMITS, cleanText, id, idList, int, isoTime, randomIdField, str, type Actions, type Ctx } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { isKemSealed, validSealed, verifyGenerationSignature, verifyGrantSignature } from "../verify.ts";
import { DEFAULT_EVERYONE, P, STAFF_PERMISSIONS, ALL_PERMISSIONS, channelIsPrivate, has, isStaff, topPosition } from "../permissions.ts";
import { accountKeysOf, byAge, countSince, latestKeysFor, profileOf, rateLimited, withRow } from "../store.ts";
import { STARTER_TEMPLATES } from "../servers/template.ts";
import { addMember, cleanAdminList, createFromTemplate, ensureDefaultServer, membersWhoCanSee, removeMember } from "../servers/build.ts";
import {
  CHANNEL_EXPIRY_CHOICES,
  CHANNEL_KINDS,
  SERVER_LIMITS,
  TAGS,
  acceptItem,
  audit,
  canHandOutKeys,
  channelChainId,
  channelIn,
  channelOut,
  chainOut,
  chainsFor,
  clearedItem,
  expectedGrants,
  generationOut,
  generationsOf,
  grantKey,
  grantOut,
  historyChainId,
  itemFields,
  latestGeneration,
  liveChainId,
  memberOut,
  memberRow,
  missingGrants,
  needRotation,
  parseChainId,
  permsOf,
  refreshAccess,
  refreshKeyStatus,
  requireAbove,
  requireMember,
  requirePerm,
  roleOut,
  serverById,
  serverOut,
  serverParts,
  touchServer,
  visiblePrivate,
} from "../servers/model.ts";

export type ServerConfig = {
  /** Email addresses that become the community server's admins when they join; the first is its owner. */
  defaultAdmins: () => string[];
};

const DAY = 86_400_000;
const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const CODE_RE = /^[A-Za-z0-9]{8,16}$/;
const HEX_RE = /^#[0-9a-fA-F]{6}$/;
const INVITE_AGES = [1800, 3600, 21_600, 43_200, 86_400, 604_800, 0];
const INVITE_USES = [0, 1, 5, 10, 25, 50, 100];
const ACCOUNT_AGE_CHOICES = [0, 5, 10, 60, 1440];
const MEMBER_AGE_CHOICES = [0, 10, 60];
const DELETE_HISTORY_CHOICES = [0, 3600, 86_400, 604_800];

const choice = <T,>(value: unknown, options: readonly T[], name: string): T => {
  if (!options.includes(value as T)) throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  return value as T;
};
const bool = (value: unknown, name: string) => {
  if (typeof value !== "boolean") throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  return value;
};

async function requireReady(sr: any, userId: string) {
  if (!(await profileOf(sr, userId))) throw new ApiError(409, "PROFILE_REQUIRED", "Choose a username first.");
  if (!(await accountKeysOf(sr, userId)).length) throw new ApiError(409, "SETUP_REQUIRED", "Finish setting up encryption first.");
}

/** A device-signed request about one server from one of its members. */
async function signedMember(ctx: Ctx, action: string) {
  const { device, data } = await signedByActiveDevice(ctx, action);
  const serverId = id(data.server_id, "server");
  const member = await requireMember(ctx.own, serverId, ctx.user.id);
  const parts = await serverParts(ctx.sr, serverId);
  return { device, data, serverId, member, parts, perms: permsOf(parts, member) };
}

/** A member's profile as others in the server see it, respecting their visibility choice. */
function cardOf(profile: any) {
  if (!profile) return null;
  const hidden = profile.profile_visibility === "nobody" || profile.profile_visibility === "conversations";
  return {
    user_id: profile.user_id,
    username: profile.username,
    display_name: hidden ? "" : profile.display_name || "",
    pronouns: hidden ? "" : profile.pronouns || "",
    bio: hidden ? "" : profile.bio || "",
    accent_color: profile.accent_color || "",
    avatar_emoji: profile.avatar_emoji || "",
  };
}

async function profilesFor(sr: any, userIds: string[]) {
  if (!userIds.length) return [];
  return sr.entities.Profile.filter({ user_id: { $in: userIds } }, "created_date", userIds.length + 10);
}

/**
 * Validate grants sent by a member, against what each recipient should have. creating: the
 * "chain|generation" the caller is making right now (they hold it without a grant of their own yet).
 */
async function checkGrants(ctx: Ctx, { parts, device, raw, gens, allowChain, creating = null }: any) {
  const { sr, user, now } = ctx;
  if (!Array.isArray(raw) || raw.length > SERVER_LIMITS.grantsPerRequest) throw new ApiError(400, "BAD_FIELD", "Too many keys in one go.");
  const serverId = parts.server.id;
  const recipients = [...new Set(raw.map((g: any) => g?.recipient_id).filter((x: any) => typeof x === "string"))] as string[];
  const members = recipients.length ? await sr.entities.ServerMember.filter({ server_id: serverId, user_id: { $in: recipients } }, "created_date", recipients.length + 5) : [];
  const existing = recipients.length ? await sr.entities.KeyGrant.filter({ server_id: serverId, user_id: { $in: [...recipients, user.id] } }, "created_date", 5000) : [];
  const latest = recipients.length ? await latestKeysFor(sr, recipients) : new Map();
  const mine = existing.filter((g: any) => g.user_id === user.id);
  const accepted: any[] = [];
  const seen = new Set<string>();
  let skipped = 0;
  for (const g of raw) {
    if (!g || typeof g !== "object") throw new ApiError(400, "BAD_GRANT", "Invalid key.");
    const chain = parseChainId(g.chain_id);
    if (!chain || chain.serverId !== serverId || !allowChain(g.chain_id)) throw new ApiError(400, "BAD_GRANT", "That key isn't for this server.");
    const generation = int(g.generation, "generation", 0, 1_000_000);
    const step = int(g.step, "step", 0, 200_000);
    const recipientId = id(g.recipient_id, "member");
    const gen = gens.find((x: any) => x.chain_id === g.chain_id && Number(x.generation) === generation);
    if (!gen) throw new ApiError(409, "STALE_SERVER_KEYS", "This server's keys changed. Refreshing and trying again.");
    // The grantor must hold this generation at or before the step they're handing on.
    const held = mine.find((x: any) => grantKey(x) === grantKey(g)) || (creating && creating === grantKey(g) ? { step: 0 } : null);
    if (!held || Number(held.step) > step) throw new ApiError(403, "NOT_HELD", "You can only pass on keys you have.");
    const target = members.find((m: any) => m.user_id === recipientId);
    if (!target) {
      skipped += 1;
      continue;
    }
    const want = expectedGrants(parts, target, gens).find((e) => grantKey(e) === grantKey(g));
    const already = existing.some((x: any) => x.user_id === recipientId && grantKey(x) === grantKey(g)) || seen.has(`${recipientId}|${grantKey(g)}`);
    if (!want || want.step !== step || already) {
      skipped += 1;
      continue;
    }
    const key = latest.get(recipientId);
    if (!key || Number(g.recipient_key_version) !== Number(key.version)) throw new ApiError(409, "STALE_KEYS", "Someone's keys changed. Refreshing and trying again.");
    const sealedText = str(g.sealed, "sealed key", 4096);
    let sealed: any;
    try {
      sealed = JSON.parse(sealedText);
    } catch {
      sealed = null;
    }
    if (!validSealed(sealed)) throw new ApiError(400, "BAD_GRANT", "Invalid sealed key.");
    if (key.kem_pub && !isKemSealed(sealed)) throw new ApiError(409, "STALE_KEYS", "Someone's keys changed. Refreshing and trying again.");
    if (g.grantor_id !== user.id || g.grantor_device_id !== device.device_id) throw new ApiError(400, "BAD_GRANT", "Invalid key.");
    const grantedAt = isoTime(g.granted_at, "time");
    if (Math.abs(now.getTime() - Date.parse(grantedAt)) > LIMITS.sentAtSkewMs) throw new ApiError(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again.");
    const row = {
      server_id: serverId, chain_id: g.chain_id, generation, step, recipient_id: recipientId, recipient_key_version: Number(key.version),
      sealed: sealedText, grantor_id: user.id, grantor_device_id: device.device_id, granted_at: grantedAt, signature: g.signature,
    };
    if (!(await verifyGrantSignature(row, device.sign_pub))) throw new ApiError(403, "SIGNATURE_INVALID", "A key's signature didn't verify.");
    seen.add(`${recipientId}|${grantKey(g)}`);
    const { recipient_id, ...rest } = row;
    accepted.push({ ...rest, user_id: recipient_id });
  }
  return { accepted, skipped, members };
}

/** What a member's app needs to show a server. Read with their own access. */
async function stateFor(own: any, serverId: string, userId: string) {
  const member = await requireMember(own, serverId, userId);
  const [servers, roles, channels, chains, gens, grants] = await Promise.all([
    own.entities.Server.filter({ audience_id: serverId }, "created_date", 1),
    own.entities.Role.filter({ server_id: serverId }, "position", SERVER_LIMITS.rolesPerServer + 5),
    own.entities.Channel.filter({ server_id: serverId }, "position", SERVER_LIMITS.channelsPerServer + 5),
    own.entities.KeyChain.filter({ server_id: serverId }, "created_date", SERVER_LIMITS.channelsPerServer + 5),
    own.entities.KeyGeneration.filter({ server_id: serverId }, "created_date", 2000),
    own.entities.KeyGrant.filter({ server_id: serverId, user_id: userId }, "created_date", 2000),
  ]);
  const server = servers[0];
  if (!server || server.status === "deleting") throw new ApiError(404, "SERVER_NOT_FOUND", "Server not found.");
  const seen = new Set<string>();
  const generations = gens.sort(byAge).filter((g: any) => {
    const k = `${g.chain_id}|${g.generation}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return {
    server: serverOut(server),
    member: memberOut(member, { self: true }),
    roles: roles.map(roleOut),
    channels: channels.map(channelOut),
    chains: chains.map(chainOut),
    generations: generations.map(generationOut),
    grants: grants.map(grantOut),
  };
}

/** Everyone in a server whose access to private channels may have changed: refresh it and their keys. */
async function afterAccessChange(sr: any, serverId: string, userIds: string[], now: Date) {
  const parts = await serverParts(sr, serverId);
  const before = new Map<string, string[]>();
  const members: any[] = [];
  for (const uid of [...new Set(userIds)]) {
    const m = await memberRow(sr, serverId, uid);
    if (!m) continue;
    members.push(m);
    const u = await sr.entities.User.get(uid).catch(() => null);
    before.set(uid, (u?.cv_access || []).filter((x: string) => parts.channels.some((c: any) => c.id === x)));
  }
  const lost = new Set<string>();
  for (const m of members) {
    const after = new Set(visiblePrivate(parts, m));
    for (const had of before.get(m.user_id) || []) if (!after.has(had)) lost.add(channelChainId(serverId, had));
    await refreshAccess(sr, m.user_id);
  }
  if (lost.size) await needRotation(sr, serverId, [...lost], "access");
  await refreshKeyStatus(sr, parts, members, now);
}

/** Checks for a role's settings that apply whether it's new or changed. */
function roleChanges(parts: any, actor: any, data: any) {
  const changes: any = {};
  if (data.permissions !== undefined) {
    const perms = int(data.permissions, "permissions", 0, ALL_PERMISSIONS) & ALL_PERMISSIONS;
    const mine = permsOf(parts, actor);
    // Nobody hands out a permission they don't have themselves.
    if ((perms & ~mine) !== 0) throw new ApiError(403, "MISSING_PERMISSION", "You can't give a role permissions you don't have.");
    changes.permissions = perms;
  }
  if (data.hoist !== undefined) changes.hoist = bool(data.hoist, "hoist");
  if (data.mentionable !== undefined) changes.mentionable = bool(data.mentionable, "mentionable");
  return changes;
}

function overwritesFrom(parts: any, raw: unknown) {
  if (!Array.isArray(raw) || raw.length > 50) throw new ApiError(400, "BAD_FIELD", "Invalid permissions.");
  const out: any[] = [];
  for (const o of raw) {
    const roleId = id(o?.role_id, "role");
    if (!parts.roles.some((r: any) => r.id === roleId)) throw new ApiError(404, "ROLE_NOT_FOUND", "Role not found.");
    if (out.some((x) => x.role_id === roleId)) continue;
    out.push({ role_id: roleId, allow: int(o.allow ?? 0, "allow", 0, ALL_PERMISSIONS) & ALL_PERMISSIONS, deny: int(o.deny ?? 0, "deny", 0, ALL_PERMISSIONS) & ALL_PERMISSIONS });
  }
  return out;
}

/** Move a channel between public and private: its rows' audience, its key chain and who can read it. */
async function applyPrivacy(ctx: Ctx, parts: any, channel: any, nowPrivate: boolean, before: any[]) {
  const { sr, now } = ctx;
  const serverId = parts.server.id;
  const audience = nowPrivate ? channel.id : serverId;
  if (Boolean(channel.private) !== nowPrivate || channel.audience_id !== audience) {
    await sr.entities.Channel.update(channel.id, { private: nowPrivate, audience_id: audience });
    await sr.entities.ServerMessage.updateMany({ channel_id: channel.id }, { $set: { audience_id: audience } });
    channel.private = nowPrivate;
    channel.audience_id = audience;
  }
  if (nowPrivate) {
    const chainId = channelChainId(serverId, channel.id);
    const [chain] = await sr.entities.KeyChain.filter({ server_id: serverId, chain_id: chainId }, "created_date", 1);
    if (!chain) await sr.entities.KeyChain.create({ server_id: serverId, audience_id: channel.id, chain_id: chainId, kind: "c", channel_id: channel.id, rotation_needed: false });
  }
  const fresh = await serverParts(sr, serverId);
  const ch = fresh.channels.find((c: any) => c.id === channel.id) || channel;
  const after = nowPrivate ? await membersWhoCanSee(sr, fresh, ch) : [];
  const affected = [...new Set([...before.map((m: any) => m.user_id), ...after.map((m: any) => m.user_id)])];
  await afterAccessChange(sr, serverId, affected, now);
}

export function serverActions(config: ServerConfig): Actions {
  const adminEmails = () => cleanAdminList(config.defaultAdmins());

  /** Everyone joins the community server once, the first time they open the app after setup. */
  async function joinDefaultOnce(ctx: Ctx) {
    const { sr, own, user, now } = ctx;
    const [profile] = await own.entities.Profile.filter({ user_id: user.id }, "created_date", 1);
    if (!profile || profile.default_server_done) return;
    if (!(await own.entities.AccountKey.filter({ user_id: user.id }, "version", 1)).length) return;
    const server = await ensureDefaultServer(sr, now);
    try {
      await addMember(sr, server, user, { listed: profile.default_listed === true, adminEmails: adminEmails(), now });
    } catch (error) {
      // Paused or full: try again next time. Banned: that's that.
      if (!(error instanceof ApiError) || error.code !== "BANNED") return;
    }
    await sr.entities.Profile.update(profile.id, { default_server_done: true });
  }

  return {
    /** Your servers and your membership of each, read with your own access. */
    async list(ctx) {
      const { own, user } = ctx;
      await joinDefaultOnce(ctx);
      const members = await own.entities.ServerMember.filter({ user_id: user.id }, "created_date", SERVER_LIMITS.serversPerUser + 10);
      const ids = [...new Set(members.map((m: any) => m.server_id))];
      const servers = ids.length ? await own.entities.Server.filter({ audience_id: { $in: ids } }, "created_date", ids.length + 5) : [];
      return {
        servers: servers.filter((s: any) => s.status !== "deleting").map(serverOut),
        members: members.map((m: any) => memberOut(m, { self: true })),
      };
    },

    async state({ own, user, body }) {
      return stateFor(own, id(body.server_id, "server"), user.id);
    },

    /** Start a server from a template. Its keys and name come next, from the creator's device. */
    async create_server(ctx) {
      const { sr, user, now } = ctx;
      const { data } = await signedByActiveDevice(ctx, "create_server");
      await requireReady(sr, user.id);
      const template = STARTER_TEMPLATES[choice(data.template ?? "blank", Object.keys(STARTER_TEMPLATES), "template")];
      const mine = await sr.entities.ServerMember.filter({ user_id: user.id }, "created_date", SERVER_LIMITS.serversPerUser + 1);
      if (mine.length >= SERVER_LIMITS.serversPerUser) throw new ApiError(409, "TOO_MANY_SERVERS", `You can be in up to ${SERVER_LIMITS.serversPerUser} servers.`);
      if ((await countSince(sr, "Server", { owner_id: user.id }, new Date(now.getTime() - DAY), SERVER_LIMITS.serversCreatedPerDay)) >= SERVER_LIMITS.serversCreatedPerDay) {
        throw rateLimited("creating servers");
      }
      const server = await createFromTemplate(sr, template, { ownerId: user.id, isDefault: false, now });
      await sr.entities.ServerMember.create({
        server_id: server.id, user_id: user.id, role_ids: [], joined_at: now.toISOString(), listed: true, rules_accepted_at: now.toISOString(), timeout_until: "", key_status: "pending",
      });
      await sr.entities.Server.update(server.id, { member_count: 1, keys_pending_at: now.toISOString() });
      await refreshAccess(sr, user.id);
      await audit(sr, server, user.id, "server_create", "server", server.id, template.key, now);
      return { server_id: server.id };
    },

    // ---------- keys ----------

    /**
     * A new key generation for one of the server's chains, made on the caller's device, with
     * copies for whoever the device could seal them to (always including itself). The first
     * generation of a chain can come from any member who can read it; later ones need
     * MANAGE_KEYS (someone was banned or removed).
     */
    async create_generation(ctx) {
      const { sr, user, now } = ctx;
      const { device, data, serverId, member, parts, perms } = await signedMember(ctx, "create_generation");
      const g = data.generation;
      if (!g || typeof g !== "object") throw new ApiError(400, "BAD_FIELD", "Missing key generation.");
      const chainId = str(g.chain_id, "key chain", 140);
      const chain = parseChainId(chainId);
      if (!chain || chain.serverId !== serverId) throw new ApiError(400, "BAD_FIELD", "That key chain isn't this server's.");
      if (!chainsFor(parts, member).includes(chainId)) throw new ApiError(403, "MISSING_PERMISSION", "You can't read that channel.");
      const [chainRow] = await sr.entities.KeyChain.filter({ server_id: serverId, chain_id: chainId }, "created_date", 1);
      if (!chainRow) throw new ApiError(404, "NOT_FOUND", "That key chain doesn't exist.");
      const gens = await generationsOf(sr, serverId);
      const latest = latestGeneration(gens, chainId);
      const generation = int(g.generation, "generation", 0, 1_000_000);
      if (generation !== (latest ? Number(latest.generation) + 1 : 0)) throw new ApiError(409, "GENERATION_TAKEN", "Someone else just renewed these keys. Refreshing.");
      if (generation > 0) requirePerm(perms, P.MANAGE_KEYS, "renew this server's keys");
      else if (!canHandOutKeys(parts, member)) requirePerm(perms, P.MANAGE_KEYS, "set up this server's keys");
      const startedAt = isoTime(g.started_at, "start time");
      if (Math.abs(now.getTime() - Date.parse(startedAt)) > LIMITS.sentAtSkewMs) throw new ApiError(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again.");
      if (latest && Date.parse(startedAt) <= Date.parse(latest.started_at)) throw new ApiError(400, "BAD_FIELD", "Invalid start time.");
      const commit = typeof g.commit === "string" && B64_RE.test(g.commit) && atob(g.commit).length === 32 ? g.commit : null;
      if (!commit) throw new ApiError(400, "BAD_FIELD", "Invalid key commitment.");
      const statement = { server_id: serverId, chain_id: chainId, generation, started_at: startedAt, commit, creator_id: user.id, device_id: device.device_id, signature: g.signature };
      if (g.creator_id !== user.id || g.device_id !== device.device_id || !(await verifyGenerationSignature(statement, device.sign_pub))) {
        throw new ApiError(403, "SIGNATURE_INVALID", "The key generation's signature didn't verify.");
      }
      const audience = chain.kind === "c" ? chain.channelId : serverId;
      const row = await sr.entities.KeyGeneration.create({ ...statement, audience_id: audience });
      const same = withRow(await sr.entities.KeyGeneration.filter({ server_id: serverId, chain_id: chainId, generation }, "created_date", 5), row);
      if (same[0].id !== row.id) {
        await sr.entities.KeyGeneration.delete(row.id);
        throw new ApiError(409, "GENERATION_TAKEN", "Someone else just renewed these keys. Refreshing.");
      }
      const allGens = [...gens, row];
      let checked;
      try {
        checked = await checkGrants(ctx, {
          parts, device, raw: data.grants, gens: allGens, allowChain: (c: string) => c === chainId, creating: grantKey({ chain_id: chainId, generation }),
        });
      } catch (error) {
        await sr.entities.KeyGeneration.delete(row.id);
        throw error;
      }
      if (!checked.accepted.some((x: any) => x.user_id === user.id && x.generation === generation)) {
        await sr.entities.KeyGeneration.delete(row.id);
        throw new ApiError(400, "BAD_FIELD", "Keep a copy of the new key for yourself.");
      }
      await sr.entities.KeyGrant.bulkCreate(checked.accepted);
      if (chainRow.rotation_needed) await sr.entities.KeyChain.update(chainRow.id, { rotation_needed: false, rotation_reason: "" });
      // Everyone else who reads this chain now needs the new key.
      await sr.entities.ServerMember.updateMany({ server_id: serverId }, { $set: { key_status: "pending" } });
      await sr.entities.Server.update(parts.server.id, { keys_pending_at: now.toISOString() });
      await refreshKeyStatus(sr, parts, checked.members.concat([member]), now);
      if (generation > 0) await audit(sr, parts.server, user.id, "keys_renewed", "chain", chainId, `generation ${generation}`, now);
      return { generation: generationOut(row), granted: checked.accepted.length };
    },

    /**
     * Who's waiting for keys the caller can pass on. The app seals them and sends them with
     * `grant`. Members only see the user ids and key versions, nothing else about them.
     */
    async pending_grants(ctx) {
      const { sr, own, user, body, now } = ctx;
      const serverId = id(body.server_id, "server");
      const me = await requireMember(own, serverId, user.id);
      const parts = await serverParts(sr, serverId);
      if (!canHandOutKeys(parts, me)) return { items: [], recipients: {}, staff_only: true };
      if (!parts.server.keys_pending_at) return { items: [], recipients: {} };
      const pending = await sr.entities.ServerMember.filter({ server_id: serverId, key_status: "pending" }, "joined_at", 60);
      if (!pending.length) {
        await sr.entities.Server.update(parts.server.id, { keys_pending_at: "" });
        return { items: [], recipients: {} };
      }
      const gens = await generationsOf(sr, serverId);
      const grants = await sr.entities.KeyGrant.filter({ server_id: serverId, user_id: { $in: [...pending.map((m: any) => m.user_id), user.id] } }, "created_date", 5000);
      const held = new Map<string, number>();
      for (const g of grants) if (g.user_id === user.id) held.set(grantKey(g), Number(g.step));
      const items: any[] = [];
      const people = new Set<string>();
      let stillWaiting = 0;
      for (const m of pending) {
        const missing = missingGrants(parts, m, gens, grants);
        if (!missing.length) {
          await sr.entities.ServerMember.update(m.id, { key_status: "ok" });
          continue;
        }
        stillWaiting += 1;
        if (m.user_id === user.id) continue;
        const doable = missing.filter((e) => held.has(grantKey(e)) && (held.get(grantKey(e)) as number) <= e.step);
        if (!doable.length || people.size >= SERVER_LIMITS.pendingBatch) continue;
        people.add(m.user_id);
        for (const e of doable) items.push({ user_id: m.user_id, ...e });
      }
      if (!stillWaiting) await sr.entities.Server.update(parts.server.id, { keys_pending_at: "" });
      const latest = people.size ? await latestKeysFor(sr, [...people]) : new Map();
      const recipients: Record<string, number> = {};
      for (const uid of people) if (latest.get(uid)) recipients[uid] = Number(latest.get(uid).version);
      void now;
      return { items: items.filter((i) => recipients[i.user_id]), recipients };
    },

    /** Copies of the server's keys for members who are waiting, sealed on the caller's device. */
    async grant_keys(ctx) {
      const { sr, now } = ctx;
      const { device, data, serverId, member, parts, perms } = await signedMember(ctx, "grant_keys");
      if (!canHandOutKeys(parts, member)) requirePerm(perms, P.MANAGE_KEYS, "hand out this server's keys");
      const gens = await generationsOf(sr, serverId);
      const chains = new Set(chainsFor(parts, member));
      const checked = await checkGrants(ctx, { parts, device, raw: data.grants, gens, allowChain: (c: string) => chains.has(c) });
      if (checked.accepted.length) await sr.entities.KeyGrant.bulkCreate(checked.accepted);
      await refreshKeyStatus(sr, parts, checked.members, now);
      return { accepted: checked.accepted.length, skipped: checked.skipped };
    },

    /** Your copies that can't be opened any more (after an account reset): drop them and wait for new ones. */
    async request_keys(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts } = await signedMember(ctx, "request_keys");
      const ids = idList(data.grant_ids, "keys", 2000);
      for (const g of await sr.entities.KeyGrant.filter({ server_id: serverId, user_id: user.id }, "created_date", 2000)) {
        if (ids.includes(g.id)) await sr.entities.KeyGrant.delete(g.id);
      }
      await refreshKeyStatus(sr, parts, [member], now);
      return { ok: true };
    },

    // ---------- joining and leaving ----------

    /** Join with an invite code, or an open server (from Discover). */
    async join_server(ctx) {
      const { sr, user, now } = ctx;
      const { data } = await signedByActiveDevice(ctx, "join_server");
      await requireReady(sr, user.id);
      const recent = await countSince(sr, "ServerMember", { user_id: user.id }, new Date(now.getTime() - 3600_000), SERVER_LIMITS.joinsPerHour);
      if (recent >= SERVER_LIMITS.joinsPerHour) throw rateLimited("joining servers");
      let server: any;
      let invite: any = null;
      if (data.invite_code !== undefined) {
        const code = typeof data.invite_code === "string" && CODE_RE.test(data.invite_code) ? data.invite_code : null;
        if (!code) throw new ApiError(404, "INVITE_INVALID", "That invite isn't valid.");
        [invite] = await sr.entities.Invite.filter({ code }, "created_date", 1);
        const expired = invite?.expires_at && Date.parse(invite.expires_at) <= now.getTime();
        const used = invite && Number(invite.max_uses) > 0 && Number(invite.uses) >= Number(invite.max_uses);
        if (!invite || invite.revoked || expired || used) throw new ApiError(404, "INVITE_INVALID", "That invite has expired or isn't valid.");
        server = await serverById(sr, invite.server_id);
        if (server.invites_paused) throw new ApiError(403, "INVITES_PAUSED", "This server's invites are paused.");
      } else {
        server = await serverById(sr, id(data.server_id, "server"));
        if (server.join_mode !== "open" || !(server.discoverable || server.is_default)) throw new ApiError(403, "INVITE_REQUIRED", "You need an invite to join this server.");
      }
      const profile = await profileOf(sr, user.id);
      const { member, joined } = await addMember(sr, server, user, { listed: profile?.default_listed === true, adminEmails: adminEmails(), now });
      if (joined && invite) await sr.entities.Invite.update(invite.id, { uses: (Number(invite.uses) || 0) + 1 });
      if (server.is_default && profile && !profile.default_server_done) await sr.entities.Profile.update(profile.id, { default_server_done: true });
      return { server_id: server.id, member: memberOut(member, { self: true }), joined };
    },

    async leave_server(ctx) {
      const { sr, user, now } = ctx;
      const { serverId, parts } = await signedMember(ctx, "leave_server");
      if (parts.server.owner_id === user.id) {
        throw new ApiError(409, "OWNER_CANNOT_LEAVE", "Transfer ownership first, or delete the server.");
      }
      await removeMember(sr, serverId, user.id, { reason: "left", now });
      return { ok: true };
    },

    /** Agree to the server's rules (needed before posting when the server asks for it). */
    async accept_rules(ctx) {
      const { sr, now } = ctx;
      const { member } = await signedMember(ctx, "accept_rules");
      await sr.entities.ServerMember.update(member.id, { rules_accepted_at: now.toISOString() });
      return { ok: true };
    },

    /** Whether you appear in the member list. Staff always do. */
    async set_listed(ctx) {
      const { sr } = ctx;
      const { data, member } = await signedMember(ctx, "set_listed");
      await sr.entities.ServerMember.update(member.id, { listed: bool(data.listed, "choice") });
      return { ok: true };
    },

    /** Your nickname here (CHANGE_NICKNAME), or someone else's (MANAGE_NICKNAMES). Encrypted. */
    async set_nickname(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "set_nickname");
      const targetId = data.user_id === undefined ? user.id : id(data.user_id, "member");
      const target = targetId === user.id ? member : await memberRow(sr, serverId, targetId);
      if (!target) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this server.");
      if (targetId === user.id) requirePerm(perms, P.CHANGE_NICKNAME, "change your nickname");
      else {
        requirePerm(perms, P.MANAGE_NICKNAMES, "change nicknames");
        requireAbove(parts, member, target, "change the nickname of");
      }
      let fields: any;
      if (data.item === null) fields = clearedItem("nick");
      else fields = itemFields("nick", await acceptItem(ctx, { kind: "nick", serverId, item: data.item, gens: await generationsOf(sr, serverId) }));
      await sr.entities.ServerMember.update(target.id, fields);
      if (targetId !== user.id) await audit(sr, parts.server, user.id, "nickname_change", "member", targetId, "", now);
      return { ok: true };
    },

    // ---------- members ----------

    /**
     * The member list: staff, and members who chose to be listed. Nobody else, whatever the
     * caller's role (member_list can narrow it further). Plus the total count.
     */
    async members(ctx) {
      const { sr, own, user, body } = ctx;
      const serverId = id(body.server_id, "server");
      await requireMember(own, serverId, user.id);
      const parts = await serverParts(sr, serverId);
      const mode = parts.server.member_list || "opt_in";
      const count = Number(parts.server.member_count) || 0;
      if (mode === "count_only") return { members: [], profiles: [], count };
      const staffRoles = parts.roles.filter((r: any) => !r.is_everyone && (Number(r.permissions) & STAFF_PERMISSIONS)).map((r: any) => r.id);
      const queries = [];
      if (staffRoles.length) queries.push(sr.entities.ServerMember.filter({ server_id: serverId, role_ids: { $in: staffRoles } }, "joined_at", 500));
      if (mode === "opt_in") queries.push(sr.entities.ServerMember.filter({ server_id: serverId, listed: true }, "joined_at", 1000));
      if (parts.server.owner_id) queries.push(sr.entities.ServerMember.filter({ server_id: serverId, user_id: parts.server.owner_id }, "joined_at", 1));
      const found = new Map<string, any>();
      for (const rows of await Promise.all(queries)) for (const m of rows) if (!found.has(m.user_id)) found.set(m.user_id, m);
      const list = [...found.values()].filter((m) => isStaff(parts.server, parts.roles, m) || (mode === "opt_in" && m.listed));
      const profiles = await profilesFor(sr, list.map((m) => m.user_id));
      return { members: list.map((m) => memberOut(m)), profiles: profiles.map(cardOf), count };
    },

    /** One member's card: anyone in a server can see who someone in it is (their messages show it anyway). */
    async member(ctx) {
      const { sr, own, user, body } = ctx;
      const serverId = id(body.server_id, "server");
      await requireMember(own, serverId, user.id);
      const targetId = id(body.user_id, "member");
      const target = await memberRow(sr, serverId, targetId);
      if (!target) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this server.");
      const [profile] = await profilesFor(sr, [targetId]);
      return { member: memberOut(target), profile: cardOf(profile) };
    },

    async kick_member(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "kick_member");
      requirePerm(perms, P.KICK_MEMBERS, "kick members");
      const targetId = id(data.user_id, "member");
      if (targetId === user.id) throw new ApiError(400, "BAD_FIELD", "To leave yourself, use Leave server.");
      const target = await memberRow(sr, serverId, targetId);
      if (!target) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this server.");
      requireAbove(parts, member, target, "kick");
      await removeMember(sr, serverId, targetId, { reason: "kicked", now });
      await audit(sr, parts.server, user.id, "member_kick", "member", targetId, "", now);
      return { ok: true };
    },

    /** Ban: out, can't come back, and the keys they held are due to be renewed. Optionally, their recent messages go. */
    async ban_member(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "ban_member");
      requirePerm(perms, P.BAN_MEMBERS, "ban members");
      const targetId = id(data.user_id, "member");
      if (targetId === user.id) throw new ApiError(400, "BAD_FIELD", "You can't ban yourself.");
      const target = await memberRow(sr, serverId, targetId);
      if (target) requireAbove(parts, member, target, "ban");
      else if (targetId === parts.server.owner_id) throw new ApiError(403, "HIERARCHY", "You can't ban the server's owner.");
      const deleteSeconds = choice(data.delete_seconds ?? 0, DELETE_HISTORY_CHOICES, "message history");
      const reason = data.reason ? itemFields("reason", await acceptItem(ctx, { kind: "ban", serverId, item: data.reason, gens: await generationsOf(sr, serverId) })) : {};
      const [existing] = await sr.entities.ServerBan.filter({ server_id: serverId, user_id: targetId }, "created_date", 1);
      if (!existing) await sr.entities.ServerBan.create({ server_id: serverId, user_id: targetId, banned_by: user.id, ...reason });
      if (target) await removeMember(sr, serverId, targetId, { reason: "banned", now });
      else await needRotation(sr, serverId, [historyChainId(serverId), liveChainId(serverId)], "banned");
      if (deleteSeconds) {
        const since = new Date(now.getTime() - deleteSeconds * 1000).toISOString().replace("Z", "");
        const rows = await sr.entities.ServerMessage.filter({ server_id: serverId, sender_id: targetId, created_date: { $gte: since } }, "created_date", 1000);
        for (const m of rows) if (!m.deleted) await sr.entities.ServerMessage.update(m.id, { envelope: "", signature: "", deleted: true, deleted_by: user.id, deleted_at: now.toISOString() });
      }
      await audit(sr, parts.server, user.id, "member_ban", "member", targetId, deleteSeconds ? `messages from the last ${deleteSeconds / 3600} h deleted` : "", now);
      return { ok: true };
    },

    async unban_member(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts, perms } = await signedMember(ctx, "unban_member");
      requirePerm(perms, P.BAN_MEMBERS, "unban members");
      const targetId = id(data.user_id, "member");
      for (const b of await sr.entities.ServerBan.filter({ server_id: serverId, user_id: targetId }, "created_date", 5)) await sr.entities.ServerBan.delete(b.id);
      await audit(sr, parts.server, user.id, "member_unban", "member", targetId, "", now);
      return { ok: true };
    },

    async bans(ctx) {
      const { sr, own, user, body } = ctx;
      const serverId = id(body.server_id, "server");
      const member = await requireMember(own, serverId, user.id);
      const parts = await serverParts(sr, serverId);
      requirePerm(permsOf(parts, member), P.BAN_MEMBERS, "see bans");
      const rows = await sr.entities.ServerBan.filter({ server_id: serverId }, "-created_date", 500);
      const profiles = await profilesFor(sr, rows.map((b: any) => b.user_id));
      return {
        bans: rows.map((b: any) => ({
          user_id: b.user_id,
          banned_by: b.banned_by,
          created_date: b.created_date,
          reason: b.reason_envelope ? { envelope: b.reason_envelope, item_id: b.reason_item_id, sender_id: b.reason_sender_id, device_id: b.reason_device_id, sent_at: b.reason_sent_at, signature: b.reason_signature } : null,
        })),
        profiles: profiles.map((p: any) => ({ user_id: p.user_id, username: p.username })),
      };
    },

    /** Time someone out (up to 28 days), or end it. Timed-out members can read but not post, react or join calls. */
    async timeout_member(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "timeout_member");
      requirePerm(perms, P.TIMEOUT_MEMBERS, "time out members");
      const targetId = id(data.user_id, "member");
      const target = await memberRow(sr, serverId, targetId);
      if (!target) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this server.");
      requireAbove(parts, member, target, "time out");
      const minutes = int(data.minutes, "length", 0, SERVER_LIMITS.timeoutMaxDays * 1440);
      const until = minutes ? new Date(now.getTime() + minutes * 60_000).toISOString() : "";
      await sr.entities.ServerMember.update(target.id, { timeout_until: until });
      await audit(sr, parts.server, user.id, minutes ? "member_timeout" : "member_timeout_end", "member", targetId, minutes ? `${minutes} min` : "", now);
      return { ok: true, timeout_until: until || null };
    },

    /** Give or take roles (only roles below your own highest; never to someone at or above you). */
    async set_member_roles(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "set_member_roles");
      requirePerm(perms, P.MANAGE_ROLES, "manage roles");
      const targetId = id(data.user_id, "member");
      const target = await memberRow(sr, serverId, targetId);
      if (!target) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this server.");
      if (targetId !== user.id) requireAbove(parts, member, target, "change the roles of");
      const wanted = idList(data.role_ids, "roles", 50);
      const top = topPosition(parts.server, parts.roles, member);
      const current: string[] = target.role_ids || [];
      for (const rid of [...new Set([...wanted, ...current])]) {
        const role = parts.roles.find((r: any) => r.id === rid);
        if (!role || role.is_everyone) {
          if (wanted.includes(rid)) throw new ApiError(404, "ROLE_NOT_FOUND", "Role not found.");
          continue;
        }
        const changing = wanted.includes(rid) !== current.includes(rid);
        if (changing && (Number(role.position) || 0) >= top) throw new ApiError(403, "HIERARCHY", "You can only give or take roles below your own.");
      }
      const roleIds = wanted.filter((rid) => parts.roles.some((r: any) => r.id === rid && !r.is_everyone));
      await sr.entities.ServerMember.update(target.id, { role_ids: roleIds });
      await afterAccessChange(sr, serverId, [targetId], now);
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "member_roles", "member", targetId, "", now);
      return { ok: true };
    },

    // ---------- roles ----------

    async create_role(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "create_role");
      requirePerm(perms, P.MANAGE_ROLES, "manage roles");
      if (parts.roles.length >= SERVER_LIMITS.rolesPerServer) throw new ApiError(409, "TOO_MANY", `A server can have up to ${SERVER_LIMITS.rolesPerServer} roles.`);
      const changes = roleChanges(parts, member, data);
      const top = topPosition(parts.server, parts.roles, member);
      const positions = parts.roles.filter((r: any) => !r.is_everyone).map((r: any) => Number(r.position) || 0);
      const position = top === Number.MAX_SAFE_INTEGER ? Math.max(0, ...positions) + 1 : Math.max(1, top - 1);
      const name = data.item ? itemFields("name", await acceptItem(ctx, { kind: "role", serverId, item: data.item, gens: await generationsOf(sr, serverId) })) : {};
      const row = await sr.entities.Role.create({
        server_id: serverId, audience_id: serverId, position, permissions: changes.permissions ?? 0, is_everyone: false, template_key: "",
        hoist: changes.hoist ?? false, mentionable: changes.mentionable ?? false, ...name,
      });
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "role_create", "role", row.id, "", now);
      return { role: roleOut(row) };
    },

    async update_role(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "update_role");
      requirePerm(perms, P.MANAGE_ROLES, "manage roles");
      const role = parts.roles.find((r: any) => r.id === id(data.role_id, "role"));
      if (!role) throw new ApiError(404, "ROLE_NOT_FOUND", "Role not found.");
      const top = topPosition(parts.server, parts.roles, member);
      if (!role.is_everyone && (Number(role.position) || 0) >= top) throw new ApiError(403, "HIERARCHY", "You can only edit roles below your own.");
      const changes = roleChanges(parts, member, data);
      if (data.item !== undefined && !role.is_everyone) {
        Object.assign(changes, data.item === null ? clearedItem("name") : itemFields("name", await acceptItem(ctx, { kind: "role", serverId, item: data.item, gens: await generationsOf(sr, serverId) })));
      }
      await sr.entities.Role.update(role.id, changes);
      if (changes.permissions !== undefined && changes.permissions !== Number(role.permissions)) {
        const affected = role.is_everyone ? [] : (await sr.entities.ServerMember.filter({ server_id: serverId, role_ids: role.id }, "joined_at", 5000)).map((m: any) => m.user_id);
        if (affected.length && parts.channels.some((c: any) => c.private)) await afterAccessChange(sr, serverId, affected, now);
      }
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "role_update", "role", role.id, Object.keys(changes).filter((k) => !k.startsWith("name_")).join(", "), now);
      return { ok: true };
    },

    async delete_role(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "delete_role");
      requirePerm(perms, P.MANAGE_ROLES, "manage roles");
      const role = parts.roles.find((r: any) => r.id === id(data.role_id, "role"));
      if (!role || role.is_everyone) throw new ApiError(404, "ROLE_NOT_FOUND", "Role not found.");
      if ((Number(role.position) || 0) >= topPosition(parts.server, parts.roles, member)) throw new ApiError(403, "HIERARCHY", "You can only delete roles below your own.");
      const holders = await sr.entities.ServerMember.filter({ server_id: serverId, role_ids: role.id }, "joined_at", 5000);
      for (const m of holders) await sr.entities.ServerMember.update(m.id, { role_ids: (m.role_ids || []).filter((r: string) => r !== role.id) });
      for (const ch of parts.channels) {
        const kept = (ch.overwrites || []).filter((o: any) => o.role_id !== role.id);
        if (kept.length !== (ch.overwrites || []).length) await sr.entities.Channel.update(ch.id, { overwrites: kept });
      }
      await sr.entities.Role.delete(role.id);
      if (holders.length) await afterAccessChange(sr, serverId, holders.map((m: any) => m.user_id), now);
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "role_delete", "role", role.id, "", now);
      return { ok: true };
    },

    /** New order for roles below your own: [{ id, position }]. */
    async reorder_roles(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "reorder_roles");
      requirePerm(perms, P.MANAGE_ROLES, "manage roles");
      if (!Array.isArray(data.order) || data.order.length > SERVER_LIMITS.rolesPerServer) throw new ApiError(400, "BAD_FIELD", "Invalid order.");
      const top = topPosition(parts.server, parts.roles, member);
      for (const o of data.order) {
        const role = parts.roles.find((r: any) => r.id === id(o?.id, "role"));
        const position = int(o?.position, "position", 1, 10_000);
        if (!role || role.is_everyone) throw new ApiError(404, "ROLE_NOT_FOUND", "Role not found.");
        if ((Number(role.position) || 0) >= top || position >= top) throw new ApiError(403, "HIERARCHY", "You can only move roles below your own.");
        if (Number(role.position) !== position) await sr.entities.Role.update(role.id, { position });
      }
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "roles_reorder", "server", serverId, "", now);
      return { ok: true };
    },

    // ---------- channels ----------

    async create_channel(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "create_channel");
      requirePerm(perms, P.MANAGE_CHANNELS, "manage channels");
      if (parts.channels.length >= SERVER_LIMITS.channelsPerServer) throw new ApiError(409, "TOO_MANY", `A server can have up to ${SERVER_LIMITS.channelsPerServer} channels.`);
      const kind = choice(data.kind, [...CHANNEL_KINDS], "channel type");
      const parentId = data.parent_id ? id(data.parent_id, "category") : "";
      if (parentId && !parts.channels.some((c: any) => c.id === parentId && c.kind === "category")) throw new ApiError(404, "CHANNEL_NOT_FOUND", "Category not found.");
      if (kind === "category" && parentId) throw new ApiError(400, "BAD_FIELD", "Categories can't go inside categories.");
      const overwrites = data.overwrites ? overwritesFrom(parts, data.overwrites) : [];
      const isPrivate = channelIsPrivate(parts.roles, { kind, overwrites });
      const history = data.history ? choice(data.history, ["full", "joined"], "history setting") : parts.server.default_history || "joined";
      const name = data.item ? itemFields("name", await acceptItem(ctx, { kind: "channel", serverId, item: data.item, gens: await generationsOf(sr, serverId) })) : {};
      const position = Math.max(0, ...parts.channels.map((c: any) => Number(c.position) || 0)) + 1;
      const row = await sr.entities.Channel.create({
        server_id: serverId, audience_id: serverId, kind, parent_id: parentId, position, template_key: "", history: isPrivate ? "full" : history,
        private: false, overwrites, slowmode_seconds: 0, expire_seconds: 0, sensitive: false, creator_id: user.id, ...name,
      });
      if (isPrivate) await applyPrivacy(ctx, parts, row, true, []);
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "channel_create", "channel", row.id, kind, now);
      void member;
      return { channel: channelOut({ ...row, private: isPrivate }) };
    },

    async update_channel(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts, perms } = await signedMember(ctx, "update_channel");
      requirePerm(perms, P.MANAGE_CHANNELS, "manage channels");
      const channel = channelIn(parts, id(data.channel_id, "channel"));
      const changes: any = {};
      const changed: string[] = [];
      if (data.item !== undefined) {
        Object.assign(changes, data.item === null ? clearedItem("name") : itemFields("name", await acceptItem(ctx, { kind: "channel", serverId, item: data.item, gens: await generationsOf(sr, serverId) })));
        changed.push("name");
      }
      if (data.parent_id !== undefined && channel.kind !== "category") {
        const parentId = data.parent_id ? id(data.parent_id, "category") : "";
        if (parentId && !parts.channels.some((c: any) => c.id === parentId && c.kind === "category")) throw new ApiError(404, "CHANNEL_NOT_FOUND", "Category not found.");
        changes.parent_id = parentId;
        changed.push("category");
      }
      if (data.history !== undefined) {
        changes.history = choice(data.history, ["full", "joined"], "history setting");
        changed.push("history");
      }
      if (data.slowmode_seconds !== undefined) {
        changes.slowmode_seconds = choice(data.slowmode_seconds, SERVER_LIMITS.slowmodeChoices, "slow mode");
        changed.push("slow mode");
      }
      if (data.expire_seconds !== undefined) {
        changes.expire_seconds = choice(data.expire_seconds, CHANNEL_EXPIRY_CHOICES, "disappearing messages");
        changed.push("disappearing messages");
      }
      if (data.sensitive !== undefined) {
        changes.sensitive = bool(data.sensitive, "content warning");
        changed.push("content warning");
      }
      let privacyChange: boolean | null = null;
      let before: any[] = [];
      if (data.overwrites !== undefined) {
        const overwrites = overwritesFrom(parts, data.overwrites);
        changes.overwrites = overwrites;
        changed.push("permissions");
        const nowPrivate = channelIsPrivate(parts.roles, { kind: channel.kind, overwrites });
        if (channel.private) before = await membersWhoCanSee(sr, parts, channel);
        privacyChange = nowPrivate;
        if (nowPrivate) changes.history = "full";
      }
      await sr.entities.Channel.update(channel.id, changes);
      if (privacyChange !== null && (privacyChange || channel.private)) await applyPrivacy(ctx, parts, { ...channel, ...changes }, privacyChange, before);
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "channel_update", "channel", channel.id, changed.join(", "), now);
      return { ok: true };
    },

    /** Delete a channel and everything in it (blanked first). A category's channels move to the top level. */
    async delete_channel(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts, perms } = await signedMember(ctx, "delete_channel");
      requirePerm(perms, P.MANAGE_CHANNELS, "manage channels");
      const channel = channelIn(parts, id(data.channel_id, "channel"));
      if (channel.kind === "category") {
        for (const c of parts.channels.filter((x: any) => x.parent_id === channel.id)) await sr.entities.Channel.update(c.id, { parent_id: "" });
      }
      const messages = await sr.entities.ServerMessage.filter({ channel_id: channel.id }, "created_date", 5000);
      for (const m of messages) {
        await sr.entities.ServerMessage.update(m.id, { envelope: "", signature: "", deleted: true });
        await sr.entities.ServerMessage.delete(m.id);
      }
      const before = channel.private ? await membersWhoCanSee(sr, parts, channel) : [];
      if (channel.private) {
        const chainId = channelChainId(serverId, channel.id);
        await sr.entities.KeyGrant.deleteMany({ server_id: serverId, chain_id: chainId });
        await sr.entities.KeyGeneration.deleteMany({ server_id: serverId, chain_id: chainId });
        await sr.entities.KeyChain.deleteMany({ server_id: serverId, chain_id: chainId });
      }
      await sr.entities.Channel.delete(channel.id);
      for (const m of before) await refreshAccess(sr, m.user_id);
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "channel_delete", "channel", channel.id, channel.kind, now);
      return { ok: true };
    },

    /** New order: [{ id, parent_id, position }]. */
    async reorder_channels(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts, perms } = await signedMember(ctx, "reorder_channels");
      requirePerm(perms, P.MANAGE_CHANNELS, "manage channels");
      if (!Array.isArray(data.order) || data.order.length > SERVER_LIMITS.channelsPerServer) throw new ApiError(400, "BAD_FIELD", "Invalid order.");
      for (const o of data.order) {
        const ch = channelIn(parts, id(o?.id, "channel"));
        const position = int(o?.position, "position", 0, 10_000);
        const parentId = o.parent_id ? id(o.parent_id, "category") : "";
        if (parentId && (ch.kind === "category" || !parts.channels.some((c: any) => c.id === parentId && c.kind === "category"))) throw new ApiError(400, "BAD_FIELD", "Invalid category.");
        if (Number(ch.position) !== position || (ch.parent_id || "") !== parentId) await sr.entities.Channel.update(ch.id, { position, parent_id: parentId });
      }
      await touchServer(sr, serverId, now);
      await audit(sr, parts.server, user.id, "channels_reorder", "server", serverId, "", now);
      return { ok: true };
    },

    // ---------- the server itself ----------

    /** Name, description and icon: encrypted with the server's history key. */
    async set_server_profile(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts, perms } = await signedMember(ctx, "set_server_profile");
      requirePerm(perms, P.MANAGE_SERVER, "change the server's profile");
      const accepted = await acceptItem(ctx, { kind: "server", serverId, item: data.item, gens: await generationsOf(sr, serverId) });
      await sr.entities.Server.update(parts.server.id, { ...itemFields("profile", accepted), changed_at: now.toISOString() });
      await audit(sr, parts.server, user.id, "server_profile", "server", serverId, "", now);
      return { ok: true };
    },

    async set_server_rules(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts, perms } = await signedMember(ctx, "set_server_rules");
      requirePerm(perms, P.MANAGE_SERVER, "change the rules");
      const fields = data.item === null ? clearedItem("rules") : itemFields("rules", await acceptItem(ctx, { kind: "rules", serverId, item: data.item, gens: await generationsOf(sr, serverId) }));
      await sr.entities.Server.update(parts.server.id, { ...fields, changed_at: now.toISOString() });
      await audit(sr, parts.server, user.id, "server_rules", "server", serverId, "", now);
      return { ok: true };
    },

    /**
     * Settings the server enforces. Listing a server in Discover publishes its public name,
     * description and tags unencrypted: that's the point of a listing, and it's opt-in.
     */
    async update_server_settings(ctx) {
      const { sr, user, now } = ctx;
      const { data, parts, perms } = await signedMember(ctx, "update_server_settings");
      requirePerm(perms, P.MANAGE_SERVER, "change the server's settings");
      const s = parts.server;
      const changes: any = {};
      if (data.join_mode !== undefined && !s.is_default) changes.join_mode = choice(data.join_mode, ["invite", "open"], "joining");
      if (data.discoverable !== undefined && !s.is_default) changes.discoverable = bool(data.discoverable, "listing");
      const listed = changes.discoverable ?? s.discoverable ?? s.is_default;
      if (data.public !== undefined) {
        const p = data.public || {};
        const name = cleanText(p.name, 60);
        if (listed && !name) throw new ApiError(400, "BAD_FIELD", "A listed server needs a public name.");
        const tags = Array.isArray(p.tags) ? [...new Set(p.tags.map((t: unknown) => choice(t, TAGS, "tag")))] : [];
        if (tags.length > 5) throw new ApiError(400, "BAD_FIELD", "Choose up to 5 tags.");
        const icon = cleanText(p.icon, 8);
        const color = p.color ? (HEX_RE.test(p.color) ? p.color : null) : "";
        if (color === null) throw new ApiError(400, "BAD_FIELD", "Invalid colour.");
        Object.assign(changes, { public_name: name, public_description: cleanText(p.description, 300), public_tags: tags, public_icon: icon, public_color: color });
      }
      if (changes.discoverable === false) Object.assign(changes, { public_name: "", public_description: "", public_tags: [], public_icon: "", public_color: "" });
      if (changes.discoverable === true && !(changes.public_name ?? s.public_name)) throw new ApiError(400, "BAD_FIELD", "A listed server needs a public name.");
      if (data.rules_required !== undefined) changes.rules_required = bool(data.rules_required, "rules screening");
      if (data.min_account_minutes !== undefined) changes.min_account_minutes = choice(data.min_account_minutes, ACCOUNT_AGE_CHOICES, "account age");
      if (data.min_member_minutes !== undefined) changes.min_member_minutes = choice(data.min_member_minutes, MEMBER_AGE_CHOICES, "membership age");
      if (data.invites_paused !== undefined) changes.invites_paused = bool(data.invites_paused, "invites");
      if (data.joins_paused !== undefined) changes.joins_paused = bool(data.joins_paused, "joining");
      if (data.member_list !== undefined) changes.member_list = choice(data.member_list, ["opt_in", "staff_only", "count_only"], "member list");
      if (data.audit_retention_days !== undefined) changes.audit_retention_days = choice(data.audit_retention_days, SERVER_LIMITS.auditRetentionChoices, "audit log retention");
      if (data.default_history !== undefined) changes.default_history = choice(data.default_history, ["full", "joined"], "history setting");
      if (data.allow_member_dms !== undefined) changes.allow_member_dms = bool(data.allow_member_dms, "direct messages");
      if (data.key_handout !== undefined) changes.key_handout = choice(data.key_handout, ["members", "staff"], "who hands out keys");
      if (!Object.keys(changes).length) return { server: serverOut(s) };
      const updated = await sr.entities.Server.update(s.id, { ...changes, changed_at: now.toISOString() });
      await audit(sr, s, user.id, "server_settings", "server", s.id, Object.keys(changes).filter((k) => !k.startsWith("public_")).concat(data.public !== undefined ? ["listing"] : []).join(", "), now);
      return { server: serverOut({ ...s, ...updated, ...changes }) };
    },

    async transfer_ownership(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts } = await signedMember(ctx, "transfer_ownership");
      if (parts.server.owner_id !== user.id) throw new ApiError(403, "NOT_OWNER", "Only the owner can hand the server on.");
      const targetId = id(data.user_id, "member");
      if (!(await memberRow(sr, serverId, targetId))) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this server.");
      await sr.entities.Server.update(parts.server.id, { owner_id: targetId, changed_at: now.toISOString() });
      await audit(sr, parts.server, user.id, "ownership_transfer", "member", targetId, "", now);
      return { ok: true };
    },

    /** Delete the server and everything in it, blanked first. The community server can't be deleted. */
    async delete_server(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts } = await signedMember(ctx, "delete_server");
      if (parts.server.owner_id !== user.id) throw new ApiError(403, "NOT_OWNER", "Only the owner can delete the server.");
      if (parts.server.is_default) throw new ApiError(403, "DEFAULT_SERVER", "The community server can't be deleted.");
      if (data.confirm !== "DELETE") throw new ApiError(400, "CONFIRM_REQUIRED", "Type DELETE to confirm.");
      const { eraseServer } = await import("../servers/erase.ts");
      const done = await eraseServer(sr, parts.server, Date.now() + 45_000);
      return { done };
    },

    // ---------- invites ----------

    /**
     * An invite link: /invite/<code>#<secret>. The code is the server's to look up; the secret
     * (after #) never reaches it, and the preview (name, description, icon) is encrypted under it.
     */
    async create_invite(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts, perms } = await signedMember(ctx, "create_invite");
      requirePerm(perms, P.CREATE_INVITES, "create invites");
      if (parts.server.invites_paused) throw new ApiError(403, "INVITES_PAUSED", "Invites are paused in this server.");
      const code = typeof data.code === "string" && CODE_RE.test(data.code) ? data.code : null;
      if (!code) throw new ApiError(400, "BAD_FIELD", "Invalid invite code.");
      const age = choice(data.max_age_seconds ?? 604_800, INVITE_AGES, "expiry");
      const uses = choice(data.max_uses ?? 0, INVITE_USES, "number of uses");
      const preview = data.preview ? str(data.preview, "preview", SERVER_LIMITS.maxPreviewChars) : "";
      const count = (await sr.entities.Invite.filter({ server_id: serverId, revoked: false }, "created_date", SERVER_LIMITS.invitesPerServer + 1)).length;
      if (count >= SERVER_LIMITS.invitesPerServer) throw new ApiError(409, "TOO_MANY", "This server has too many invites. Revoke some first.");
      if ((await sr.entities.Invite.filter({ code }, "created_date", 1)).length) throw new ApiError(409, "CODE_TAKEN", "Try again.");
      const row = await sr.entities.Invite.create({
        server_id: serverId, code, creator_id: user.id, channel_id: data.channel_id ? id(data.channel_id, "channel") : "",
        expires_at: age ? new Date(now.getTime() + age * 1000).toISOString() : "", max_uses: uses, uses: 0, revoked: false, preview,
      });
      await audit(sr, parts.server, user.id, "invite_create", "invite", row.id, inviteSummary(age, uses), now);
      return { invite: inviteOut(row) };
    },

    async invites(ctx) {
      const { sr, own, user, body, now } = ctx;
      const serverId = id(body.server_id, "server");
      const member = await requireMember(own, serverId, user.id);
      const parts = await serverParts(sr, serverId);
      const all = has(permsOf(parts, member), P.MANAGE_INVITES);
      const rows = await sr.entities.Invite.filter(all ? { server_id: serverId, revoked: false } : { server_id: serverId, revoked: false, creator_id: user.id }, "-created_date", 500);
      return { invites: rows.filter((i: any) => !i.expires_at || Date.parse(i.expires_at) > now.getTime()).map(inviteOut) };
    },

    async revoke_invite(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, parts, perms } = await signedMember(ctx, "revoke_invite");
      const [invite] = await sr.entities.Invite.filter({ server_id: serverId, code: str(data.code, "code", 16) }, "created_date", 1);
      if (!invite) throw new ApiError(404, "NOT_FOUND", "Invite not found.");
      if (invite.creator_id !== user.id) requirePerm(perms, P.MANAGE_INVITES, "revoke other people's invites");
      await sr.entities.Invite.update(invite.id, { revoked: true, preview: "" });
      await audit(sr, parts.server, user.id, "invite_revoke", "invite", invite.id, "", now);
      return { ok: true };
    },

    // ---------- discovery ----------

    /** Servers whose admins chose to list them. Member counts are rounded. */
    async discover({ sr, body }) {
      const tag = body.tag ? choice(body.tag, TAGS, "tag") : null;
      const rows = await sr.entities.Server.filter(tag ? { discoverable: true, public_tags: tag } : { discoverable: true }, "-member_count", 100);
      return {
        servers: rows
          .filter((s: any) => s.status !== "deleting" && s.public_name)
          .map((s: any) => ({
            id: s.id,
            is_default: Boolean(s.is_default),
            join_mode: s.join_mode,
            name: s.public_name,
            description: s.public_description || "",
            tags: s.public_tags || [],
            icon: s.public_icon || "",
            color: s.public_color || "",
            member_count: roundCount(Number(s.member_count) || 0),
          })),
        tags: TAGS,
      };
    },

    // ---------- audit log ----------

    async audit_log(ctx) {
      const { sr, own, user, body, now } = ctx;
      const serverId = id(body.server_id, "server");
      const member = await requireMember(own, serverId, user.id);
      const parts = await serverParts(sr, serverId);
      requirePerm(permsOf(parts, member), P.VIEW_AUDIT_LOG, "see the audit log");
      const rows = await sr.entities.AuditEntry.filter({ server_id: serverId }, "-created_date", 200);
      const live = rows.filter((a: any) => Date.parse(a.expires_at) > now.getTime());
      const people = [...new Set(live.flatMap((a: any) => [a.actor_id, a.target_kind === "member" ? a.target_id : ""]).filter(Boolean))] as string[];
      const profiles = await profilesFor(sr, people);
      return {
        entries: live.map((a: any) => ({ id: a.id, actor_id: a.actor_id, action: a.action, target_kind: a.target_kind, target_id: a.target_id, detail: a.detail || "", at: a.created_date })),
        profiles: profiles.map((p: any) => ({ user_id: p.user_id, username: p.username })),
        retention_days: Number(parts.server.audit_retention_days) || 90,
      };
    },

    // ---------- support tickets ----------

    /**
     * Open a support ticket: a private, end-to-end encrypted group with the server's support
     * team (members who can handle tickets, up to 31 of them). You see who's in it before you send.
     */
    async open_ticket(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts, perms } = await signedMember(ctx, "open_ticket");
      const channel = channelIn(parts, id(data.channel_id, "channel"));
      if (channel.kind !== "tickets") throw new ApiError(400, "BAD_FIELD", "Tickets are opened from a tickets channel.");
      requirePerm(permsOf(parts, member, channel), P.VIEW_CHANNEL, "open tickets here");
      if (member.timeout_until && Date.parse(member.timeout_until) > now.getTime()) throw new ApiError(403, "TIMED_OUT", "You're timed out in this server.");
      const mine = await sr.entities.Conversation.filter({ server_id: serverId, ticket_opened_by: user.id, ticket_status: "open" }, "created_date", 10);
      if (mine.length >= SERVER_LIMITS.ticketsOpenPerMember) throw new ApiError(429, "TOO_MANY_TICKETS", "You have the most open tickets you can have here. Close one first.");
      const ticketRoles = parts.roles.filter((r: any) => !r.is_everyone && (Number(r.permissions) & (P.MANAGE_TICKETS | P.ADMINISTRATOR))).map((r: any) => r.id);
      const staffRows = ticketRoles.length ? await sr.entities.ServerMember.filter({ server_id: serverId, role_ids: { $in: ticketRoles } }, "joined_at", 200) : [];
      if (parts.server.owner_id && !staffRows.some((m: any) => m.user_id === parts.server.owner_id)) {
        const owner = await memberRow(sr, serverId, parts.server.owner_id);
        if (owner) staffRows.push(owner);
      }
      // Support roles first, then everyone else who can handle tickets.
      const ready = new Set((await latestKeysFor(sr, staffRows.map((m: any) => m.user_id))).keys());
      const staff = staffRows
        .filter((m: any) => m.user_id !== user.id && ready.has(m.user_id) && has(permsOf(parts, m), P.MANAGE_TICKETS))
        .sort((a: any, b: any) => topPosition(parts.server, parts.roles, a) - topPosition(parts.server, parts.roles, b))
        .slice(0, SERVER_LIMITS.staffPerTicket)
        .map((m: any) => m.user_id);
      if (!staff.length) throw new ApiError(409, "NO_SUPPORT_TEAM", "This server doesn't have a support team yet.");
      const count = await sr.entities.Conversation.filter({ server_id: serverId }, "-ticket_number", 1);
      const number = (Number(count[0]?.ticket_number) || 0) + 1;
      const conv = await sr.entities.Conversation.create({
        kind: "group", member_ids: [user.id, ...staff], admin_ids: [user.id, ...staff], creator_id: user.id,
        server_id: serverId, ticket_channel_id: channel.id, ticket_number: number, ticket_status: "open", ticket_opened_by: user.id,
      });
      void perms;
      return { conversation_id: conv.id, ticket_number: number, staff };
    },

    /** Your tickets in a server: the ones you opened, and, for the support team, the ones you're in. */
    async tickets({ own, user, body }) {
      const serverId = id(body.server_id, "server");
      await requireMember(own, serverId, user.id);
      const rows = await own.entities.Conversation.filter({ server_id: serverId, member_ids: user.id }, "-created_date", 200);
      return {
        tickets: rows.map((c: any) => ({
          conversation_id: c.id, number: Number(c.ticket_number) || 0, status: c.ticket_status || "open", opened_by: c.ticket_opened_by,
          channel_id: c.ticket_channel_id || "", created_date: c.created_date, last_message_at: c.last_message_at || null,
        })),
      };
    },

    async set_ticket_status(ctx) {
      const { sr, user, now } = ctx;
      const { data, serverId, member, parts } = await signedMember(ctx, "set_ticket_status");
      const conv = await sr.entities.Conversation.get(id(data.conversation_id, "ticket")).catch(() => null);
      if (!conv || conv.server_id !== serverId || !(conv.member_ids || []).includes(user.id)) throw new ApiError(404, "NOT_FOUND", "Ticket not found.");
      if (conv.ticket_opened_by !== user.id) requirePerm(permsOf(parts, member), P.MANAGE_TICKETS, "close other people's tickets");
      const status = choice(data.status, ["open", "closed"], "status");
      await sr.entities.Conversation.update(conv.id, { ticket_status: status });
      await audit(sr, parts.server, user.id, status === "closed" ? "ticket_close" : "ticket_reopen", "ticket", conv.id, `#${conv.ticket_number}`, now);
      return { ok: true };
    },
  };
}

export const inviteOut = (i: any) => ({
  code: i.code,
  server_id: i.server_id,
  creator_id: i.creator_id,
  channel_id: i.channel_id || "",
  expires_at: i.expires_at || null,
  max_uses: Number(i.max_uses) || 0,
  uses: Number(i.uses) || 0,
  created_date: i.created_date,
});

/** Rough numbers: exact member counts of small servers say too much. */
export function roundCount(n: number) {
  if (n < 10) return n;
  if (n < 100) return Math.round(n / 5) * 5;
  if (n < 1000) return Math.round(n / 10) * 10;
  return Math.round(n / 100) * 100;
}

/**
 * What someone opening an invite link sees, signed in or not: the encrypted preview (only the
 * link opens it), or a listed server's public card. Never who made the invite.
 */
export const inviteActions: Actions = {
  async invite_info({ sr, body, now }) {
    const code = typeof body.code === "string" && CODE_RE.test(body.code) ? body.code : null;
    if (!code) throw new ApiError(404, "INVITE_INVALID", "That invite isn't valid.");
    const [invite] = await sr.entities.Invite.filter({ code }, "created_date", 1);
    const expired = invite?.expires_at && Date.parse(invite.expires_at) <= now.getTime();
    const used = invite && Number(invite.max_uses) > 0 && Number(invite.uses) >= Number(invite.max_uses);
    if (!invite || invite.revoked || expired || used) throw new ApiError(404, "INVITE_INVALID", "That invite has expired or isn't valid.");
    const [server] = await sr.entities.Server.filter({ audience_id: invite.server_id }, "created_date", 1);
    if (!server || server.status === "deleting") throw new ApiError(404, "INVITE_INVALID", "That invite isn't valid.");
    return {
      server_id: server.id,
      preview: invite.preview || "",
      public: server.discoverable || server.is_default ? { name: server.public_name || "", description: server.public_description || "", icon: server.public_icon || "", color: server.public_color || "" } : null,
      member_count: roundCount(Number(server.member_count) || 0),
      expires_at: invite.expires_at || null,
    };
  },
};

export { DEFAULT_EVERYONE };
