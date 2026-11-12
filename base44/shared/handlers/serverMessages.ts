// Messages in server channels. Like direct messages, the service checks who's sending, the
// device and its signature, and stores ciphertext it can't read. Unlike them, every member of
// a channel reads with the channel's shared key, so a message is one row however big the server.
//
// One thing the service does see: whether a row is a message, a reaction, an edit or a forum
// post (`kind`). It needs that to apply channel permissions (in announcement channels members can
// react but not post). Readers check the encrypted payload says the same, or ignore the row.
import { ApiError, LIMITS, id, int, isoTime, parsePlatformTime, platformTime, randomIdField, str, type Actions } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { checkSentAt, verifyServerItemSignature } from "../verify.ts";
import { P, channelPermissions, has } from "../permissions.ts";
import { countSince, profileOf, rateLimited, requireActiveDevice } from "../store.ts";
import { floodedBy, logCase } from "../servers/moderation.ts";
import {
  MESSAGE_KINDS,
  SERVER_LIMITS,
  audit,
  chainForChannel,
  generationsOf,
  latestGeneration,
  parseItemEnvelope,
  requireMember,
  requirePerm,
  serverMessageOut,
  serverOut,
  serverParts,
  stepAt,
} from "../servers/model.ts";

const KINDS = ["message", "reaction", "edit", "post"] as const;

/** The caller's view of one channel, read with their own access: the row rules hide private channels they can't see. */
async function channelView(own: any, serverId: string, channelId: string, userId: string) {
  const member = await requireMember(own, serverId, userId);
  const [servers, roles, channels] = await Promise.all([
    own.entities.Server.filter({ audience_id: serverId }, "created_date", 1),
    own.entities.Role.filter({ server_id: serverId }, "position", SERVER_LIMITS.rolesPerServer + 5),
    own.entities.Channel.filter({ server_id: serverId }, "position", SERVER_LIMITS.channelsPerServer + 5),
  ]);
  const server = servers[0];
  const channel = channels.find((c: any) => c.id === channelId);
  if (!server || server.status === "deleting" || !channel) throw new ApiError(404, "CHANNEL_NOT_FOUND", "Channel not found.");
  const perms = channelPermissions(server, roles, member, channel);
  if (!has(perms, P.VIEW_CHANNEL)) throw new ApiError(404, "CHANNEL_NOT_FOUND", "Channel not found.");
  return { member, server, roles, channel, perms };
}

const isLive = (m: any, now: Date) => !m.expires_at || Date.parse(m.expires_at) > now.getTime();

/**
 * Messages before someone joined, in a channel that only shows newcomers what came after. Both
 * times are the server's own (when the row was stored, when they joined), so no clock can shift them.
 */
function hiddenFromNewcomer(view: any, m: any) {
  const joinedOnly = view.channel.history === "joined" || !has(view.perms, P.READ_HISTORY);
  return joinedOnly && parsePlatformTime(String(m.created_date)) < Date.parse(view.member.joined_at);
}

/**
 * Of these messages, the ones this member may read right now: worked out from the server's current
 * roles, overwrites and their membership (never from a stored access list that may lag behind a
 * permission change, CV-05), and with the same history rule as listing (CV-06). Read with the
 * member's own access: rows they can't read can only make the answer smaller.
 */
async function readableNow(own: any, userId: string, rows: any[]) {
  if (!rows.length) return rows;
  const serverIds = [...new Set(rows.map((m) => m.server_id).filter(Boolean))] as string[];
  const channelIds = [...new Set(rows.map((m) => m.channel_id).filter(Boolean))] as string[];
  const [members, servers, roles, channels] = await Promise.all([
    own.entities.ServerMember.filter({ user_id: userId, server_id: { $in: serverIds } }, "created_date", serverIds.length + 5),
    own.entities.Server.filter({ audience_id: { $in: serverIds } }, "created_date", serverIds.length + 5),
    own.entities.Role.filter({ server_id: { $in: serverIds } }, "position", (SERVER_LIMITS.rolesPerServer + 5) * serverIds.length),
    own.entities.Channel.filter({ id: { $in: channelIds } }, "position", channelIds.length + 5),
  ]);
  const views = new Map<string, any>();
  const viewFor = (serverId: string, channelId: string) => {
    const key = `${serverId}|${channelId}`;
    if (views.has(key)) return views.get(key);
    const member = members.find((m: any) => m.server_id === serverId);
    const server = servers.find((s: any) => s.audience_id === serverId || s.id === serverId);
    const channel = channels.find((c: any) => c.id === channelId && c.server_id === serverId);
    let view = null;
    if (member && server && server.status !== "deleting" && channel) {
      const perms = channelPermissions(server, roles.filter((r: any) => r.server_id === serverId), member, channel);
      if (has(perms, P.VIEW_CHANNEL)) view = { member, server, channel, perms };
    }
    views.set(key, view);
    return view;
  };
  return rows.filter((m) => {
    const view = viewFor(m.server_id, m.channel_id);
    return view && !hiddenFromNewcomer(view, m);
  });
}

export const serverMessageActions: Actions = {
  async send({ sr, own, user, body, now }) {
    const serverId = id(body.server_id, "server");
    const view = await channelView(own, serverId, id(body.channel_id, "channel"), user.id);
    const { member, server, channel, perms } = view;
    if (!MESSAGE_KINDS.has(channel.kind)) throw new ApiError(400, "BAD_FIELD", "You can't post in this kind of channel.");
    const kind = KINDS.includes(body.kind) ? body.kind : null;
    if (!kind) throw new ApiError(400, "BAD_FIELD", "Invalid message kind.");
    const threadId = body.thread_id ? randomIdField(body.thread_id, "post") : "";
    if (kind === "post") {
      if (channel.kind !== "forum" || threadId) throw new ApiError(400, "BAD_FIELD", "Posts start in forum channels.");
      requirePerm(perms, P.CREATE_POSTS, "start posts here");
    } else if (kind === "reaction") {
      requirePerm(perms, P.ADD_REACTIONS, "react here");
    } else {
      requirePerm(perms, P.SEND_MESSAGES, "post here");
      if (channel.kind === "forum" && !threadId) throw new ApiError(400, "BAD_FIELD", "In a forum, reply to a post or start one.");
    }
    if (member.timeout_until && Date.parse(member.timeout_until) > now.getTime()) throw new ApiError(403, "TIMED_OUT", "You're timed out in this server for now.");
    const staff = has(perms, P.MANAGE_MESSAGES) || has(perms, P.MANAGE_SERVER);
    if (!staff) {
      if (server.rules_required && !member.rules_accepted_at) throw new ApiError(403, "RULES_REQUIRED", "Read and accept the server's rules first.");
      const memberMinutes = Number(server.min_member_minutes) || 0;
      if (memberMinutes && now.getTime() - Date.parse(member.joined_at) < memberMinutes * 60_000) {
        throw new ApiError(403, "TOO_NEW", `New members can post ${memberMinutes} minutes after joining.`);
      }
      const accountMinutes = Number(server.min_account_minutes) || 0;
      if (accountMinutes) {
        const profile = await profileOf(own, user.id);
        if (!profile || now.getTime() - Date.parse(String(profile.created_date).replace(/Z?$/, "Z")) < accountMinutes * 60_000) {
          throw new ApiError(403, "ACCOUNT_TOO_NEW", "Your account is too new to post here yet.");
        }
      }
    }
    // A thread hangs off a forum post, or off an ordinary message in a text channel.
    let root: any = null;
    if (threadId) {
      [root] = await own.entities.ServerMessage.filter({ channel_id: channel.id, msg_id: threadId }, "created_date", 1);
      const fits = root && !root.deleted && (channel.kind === "forum" ? root.kind === "post" : root.kind === "message" && !root.thread_id);
      if (!fits) throw new ApiError(404, "NOT_FOUND", channel.kind === "forum" ? "That post isn't here any more." : "That thread isn't here any more.");
      if (root.thread_locked && !has(perms, P.MANAGE_THREADS) && kind !== "reaction") throw new ApiError(403, "THREAD_LOCKED", "This thread is locked.");
    }
    const device = await requireActiveDevice(own, user.id, randomIdField(body.device_id, "device id"));
    const msgId = randomIdField(body.msg_id, "message id");
    const sentAt = isoTime(body.sent_at, "sent time");
    checkSentAt(sentAt, now, body.queued);
    const envelope = str(body.envelope, "message", SERVER_LIMITS.maxMessageEnvelopeChars);
    const env = parseItemEnvelope(envelope);
    const chainId = chainForChannel(serverId, channel);
    const [gens, chainRows] = await Promise.all([
      own.entities.KeyGeneration.filter({ server_id: serverId, chain_id: chainId }, "created_date", 500),
      own.entities.KeyChain.filter({ server_id: serverId, chain_id: chainId }, "created_date", 1),
    ]);
    const latest = latestGeneration(gens, chainId);
    // Someone who held this key lost access (a removed device, a ban, a permission change): nothing
    // new is sealed with it until a moderator's app has renewed it (CV-04, CV-05).
    if (chainRows[0]?.rotation_needed) {
      throw new ApiError(409, "KEYS_RENEWING", "This channel's keys are being renewed after someone lost access. You can post again as soon as a moderator's app has renewed them, usually within moments.");
    }
    if (!latest) throw new ApiError(409, "NO_KEYS_YET", "This channel's encryption is still being set up. Try again in a moment.");
    if (env.chain !== chainId || env.gen !== Number(latest.generation) || env.step !== stepAt(chainId, latest.started_at, Date.parse(sentAt))) {
      throw new ApiError(409, "STALE_SERVER_KEYS", "This channel's keys changed. Refreshing and trying again.");
    }
    const ok = await verifyServerItemSignature({
      kind: "message", server_id: serverId, channel_id: channel.id, item_id: msgId, sender_id: user.id, device_id: device.device_id,
      envelope, sent_at: sentAt, signature: body.signature, signPub: device.sign_pub,
    });
    if (!ok) throw new ApiError(403, "SIGNATURE_INVALID", "The message signature didn't verify, so it wasn't sent.");
    const duplicate = await own.entities.ServerMessage.filter({ channel_id: channel.id, msg_id: msgId }, "created_date", 1);
    if (duplicate.length) {
      if (duplicate[0].sender_id !== user.id) throw new ApiError(409, "DUPLICATE_ID", "That message id is already taken. Please try again.");
      return { message: serverMessageOut(duplicate[0]), duplicate: true };
    }
    if (!staff && (kind === "message" || kind === "post") && Number(channel.slowmode_seconds) > 0) {
      const [last] = await own.entities.ServerMessage.filter({ channel_id: channel.id, sender_id: user.id, kind: { $in: ["message", "post"] } }, "-created_date", 1);
      const wait = last ? Date.parse(String(last.created_date).replace(/Z?$/, "Z")) + Number(channel.slowmode_seconds) * 1000 - now.getTime() : 0;
      if (wait > 0) throw new ApiError(429, "SLOWMODE", `Slow mode is on here: you can post again in ${Math.ceil(wait / 1000)} seconds.`);
    }
    const recent = await countSince(own, "ServerMessage", { sender_id: user.id }, new Date(now.getTime() - 60_000), SERVER_LIMITS.messagesPerMinute);
    if (recent >= SERVER_LIMITS.messagesPerMinute) throw rateLimited("sending messages");
    // The server's flood protection: too many messages too fast, and you're timed out for a bit.
    if (!staff && (kind === "message" || kind === "post")) {
      const flood = await floodedBy(sr, server, user.id, now);
      if (flood) {
        const until = new Date(now.getTime() + flood.timeout_minutes * 60_000).toISOString();
        await sr.entities.ServerMember.update(member.id, { timeout_until: until });
        await logCase(sr, server, { action: "timeout", targetId: user.id, actorId: "system", minutes: flood.timeout_minutes, now });
        await audit(sr, server, "system", "member_timeout", "member", user.id, `flood protection, ${flood.timeout_minutes} min`, now);
        throw new ApiError(429, "FLOOD", `That's too many messages too quickly for this server, so you're timed out for ${flood.timeout_minutes} minute${flood.timeout_minutes === 1 ? "" : "s"}.`);
      }
    }
    const lifetime = Number(channel.expire_seconds) || 0;
    const message = await sr.entities.ServerMessage.create({
      server_id: serverId, channel_id: channel.id, audience_id: channel.private ? channel.id : serverId,
      msg_id: msgId, kind, thread_id: threadId, sender_id: user.id, device_id: device.device_id,
      envelope, signature: body.signature, sent_at: sentAt, deleted: false, pinned: false,
      ...(kind === "post" ? { last_reply_at: platformTime(now), reply_count: 0 } : {}),
      ...(lifetime > 0 ? { expires_at: new Date(now.getTime() + lifetime * 1000).toISOString() } : {}),
    });
    if (kind === "message" || kind === "post") await sr.entities.Channel.update(channel.id, { last_message_at: message.created_date || platformTime(now) });
    if (root && kind === "message") {
      await sr.entities.ServerMessage.update(root.id, { last_reply_at: message.created_date || platformTime(now), reply_count: (Number(root.reply_count) || 0) + 1 });
    }
    return { message: serverMessageOut(message) };
  },

  /**
   * Page back through a channel, a forum's posts, or one post's replies. Read with the caller's
   * own access. In channels that only show newcomers what came after they joined, earlier
   * messages aren't listed (and couldn't be read with the keys they were given).
   */
  async list({ own, user, body, now }) {
    const serverId = id(body.server_id, "server");
    const view = await channelView(own, serverId, id(body.channel_id, "channel"), user.id);
    const limit = body.limit === undefined ? SERVER_LIMITS.pageSize : int(body.limit, "limit", 1, SERVER_LIMITS.pageSize);
    let query: any;
    let sort = "-created_date";
    if (body.posts) {
      query = { channel_id: view.channel.id, kind: "post" };
      sort = "-last_reply_at";
      if (body.before !== undefined) query.last_reply_at = { $lt: str(body.before, "cursor", 40) };
    } else {
      query = { channel_id: view.channel.id, thread_id: body.thread_id ? randomIdField(body.thread_id, "post") : "" };
      if (body.before !== undefined) query.created_date = { $lt: str(body.before, "cursor", 40) };
    }
    const rows = await own.entities.ServerMessage.filter(query, sort, limit + 1);
    const page = rows.slice(0, limit);
    let extra: any[] = [];
    if (body.thread_id && body.before === undefined) {
      extra = await own.entities.ServerMessage.filter({ channel_id: view.channel.id, msg_id: body.thread_id }, "created_date", 1);
    }
    const cursorField = body.posts ? "last_reply_at" : "created_date";
    // Oldest first, with a post ahead of its replies.
    return {
      messages: [...extra, ...[...page].reverse()]
        .filter((m: any) => isLive(m, now) && !hiddenFromNewcomer(view, m))
        .map(serverMessageOut),
      has_more: rows.length > limit,
      before: page.length ? page[page.length - 1][cursorField] : null,
    };
  },

  /** Pinned messages in a channel. */
  async pins({ own, user, body, now }) {
    const serverId = id(body.server_id, "server");
    const view = await channelView(own, serverId, id(body.channel_id, "channel"), user.id);
    const rows = await own.entities.ServerMessage.filter({ channel_id: view.channel.id, pinned: true }, "-created_date", 50);
    return { messages: rows.filter((m: any) => isLive(m, now) && !m.deleted && !hiddenFromNewcomer(view, m)).map(serverMessageOut) };
  },

  /** Delete a message: your own, or anyone's with MANAGE_MESSAGES. It's blanked for everyone. */
  async delete_server_message(ctx) {
    const { sr, own, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "delete_server_message");
    const serverId = id(data.server_id, "server");
    const [message] = await own.entities.ServerMessage.filter({ server_id: serverId, channel_id: id(data.channel_id, "channel"), msg_id: randomIdField(data.msg_id, "message") }, "created_date", 1);
    if (!message) throw new ApiError(404, "NOT_FOUND", "Message not found.");
    if (message.sender_id !== user.id) {
      const view = await channelView(own, serverId, message.channel_id, user.id);
      requirePerm(view.perms, P.MANAGE_MESSAGES, "delete other people's messages");
      const parts = await serverParts(sr, serverId);
      await audit(sr, parts.server, user.id, "message_delete", "member", message.sender_id, "", now);
    }
    if (!message.deleted) {
      await sr.entities.ServerMessage.update(message.id, { envelope: "", signature: "", deleted: true, deleted_by: user.id, deleted_at: now.toISOString(), pinned: false });
    }
    return { ok: true };
  },

  async pin_server_message(ctx) {
    const { sr, own, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "pin_server_message");
    const serverId = id(data.server_id, "server");
    const view = await channelView(own, serverId, id(data.channel_id, "channel"), user.id);
    requirePerm(view.perms, P.MANAGE_MESSAGES, "pin messages");
    const [message] = await own.entities.ServerMessage.filter({ channel_id: view.channel.id, msg_id: randomIdField(data.msg_id, "message") }, "created_date", 1);
    if (!message || message.deleted) throw new ApiError(404, "NOT_FOUND", "Message not found.");
    const pinned = data.pinned !== false;
    await sr.entities.ServerMessage.update(message.id, { pinned });
    const parts = await serverParts(sr, serverId);
    await audit(sr, parts.server, user.id, pinned ? "message_pin" : "message_unpin", "channel", view.channel.id, "", now);
    return { ok: true };
  },

  /** Lock or unlock a thread (or forum post): while locked, only people who can manage threads reply. */
  async lock_thread(ctx) {
    const { sr, own, user, now } = ctx;
    const { data } = await signedByActiveDevice(ctx, "lock_thread");
    const serverId = id(data.server_id, "server");
    const view = await channelView(own, serverId, id(data.channel_id, "channel"), user.id);
    requirePerm(view.perms, P.MANAGE_THREADS, "lock threads");
    const [root] = await own.entities.ServerMessage.filter({ channel_id: view.channel.id, msg_id: randomIdField(data.msg_id, "message") }, "created_date", 1);
    if (!root || root.deleted || root.thread_id || !(root.kind === "post" || root.kind === "message")) throw new ApiError(404, "NOT_FOUND", "Thread not found.");
    const locked = data.locked !== false;
    await sr.entities.ServerMessage.update(root.id, { thread_locked: locked });
    const parts = await serverParts(sr, serverId);
    await audit(sr, parts.server, user.id, locked ? "thread_lock" : "thread_unlock", "channel", view.channel.id, "", now);
    return { ok: true };
  },
};

/**
 * Server changes for a member's poll (messages.poll calls this when asked), with the member's
 * own access. Every time: messages in their servers and private channels since `since` (one
 * query). Now and then (changesSince given): servers whose rows changed, on their own cursor,
 * and which servers they're in (two more queries).
 */
export async function pollServers(
  own: any,
  userId: string,
  { since, changesSince }: { since: string; changesSince?: string },
  settled: string,
  limit: number,
  now: Date,
) {
  const withChanges = changesSince !== undefined;
  const [rows, servers, memberships] = await Promise.all([
    own.entities.ServerMessage.filter({ updated_date: { $gte: since } }, "updated_date", limit + 1),
    withChanges ? own.entities.Server.filter({ updated_date: { $gte: changesSince } }, "updated_date", 100) : Promise.resolve(null),
    withChanges ? own.entities.ServerMember.filter({ user_id: userId }, "created_date", SERVER_LIMITS.serversPerUser + 10) : Promise.resolve(null),
  ]);
  const page = rows.slice(0, limit);
  const hasMore = rows.length > limit;
  let cursor = since;
  for (const m of page) if (String(m.updated_date) > cursor) cursor = String(m.updated_date);
  if (!hasMore && cursor > settled) cursor = settled > since ? settled : since;
  const visible = await readableNow(own, userId, page.filter((m: any) => isLive(m, now)));
  const out: Record<string, unknown> = {
    server_messages: visible.map(serverMessageOut),
    servers_cursor: cursor,
    servers_more: hasMore,
  };
  if (withChanges) {
    let changesCursor = changesSince as string;
    for (const s of servers) if (String(s.updated_date) > changesCursor) changesCursor = String(s.updated_date);
    if (changesCursor > settled) changesCursor = settled > (changesSince as string) ? settled : (changesSince as string);
    Object.assign(out, {
      servers: servers.filter((s: any) => s.status !== "deleting").map((s: any) => serverOut(s, { sets: false })),
      server_ids: [...new Set(memberships.map((m: any) => m.server_id))],
      server_changes_cursor: changesCursor,
    });
  }
  return out;
}
